"""
tempid.core — Secure, self-expiring token engine.

Token format (v2)
-----------------
A token is a Base32 string formatted as ``TEMP-V2.<header>.<payload>.<signature>``

Security model
--------------
The HMAC-SHA256 signature (keyed with ``TEMPID_SECRET``) covers the header and payload.
The payload is authenticated and encrypted using AES-GCM.

Set the secret via the environment before starting your application::

    export TEMPID_SECRET="$(python -c 'import secrets; print(secrets.token_hex(32))')"

If the secret is not set, a :class:`UserWarning` is issued once and an
insecure hardcoded fallback is used.  **Never deploy to production without
setting the secret.**
"""

from __future__ import annotations

import base64
import binascii
import hmac
import inspect
import json
import os
import re
import struct
import threading
import time
import warnings
import zlib
from typing import Any, Callable

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidTag

from .backends import BaseBackend, AsyncBaseBackend, MemoryBackend
from .exceptions import (
    TempIDFormatError,
    TempIDPayloadTooLargeError,
    TempIDTamperedError,
)

# ---------------------------------------------------------------------------
# Backend configuration
# ---------------------------------------------------------------------------

_backend: BaseBackend | AsyncBaseBackend = MemoryBackend()
_backend_is_async: bool = False
_backend_lock = threading.Lock()


def configure(store: BaseBackend | AsyncBaseBackend) -> None:
    """Set the global use-count backend.

    Call this once at application startup before handling any requests.

    Example::

        from tempid import configure
        from tempid.backends import RedisBackend

        configure(store=RedisBackend("redis://localhost:6379"))
    """
    global _backend, _backend_is_async
    with _backend_lock:
        _backend = store
        # Check async capability once at configure time, not on every hot-path method call.
        # Also gracefully handles decorators on the increment_use method by checking the underlying backend.
        _backend_is_async = inspect.iscoroutinefunction(getattr(store, "increment_use", None))

def teardown() -> None:
    """Close the active sync backend and release connections.
    
    Call this on application shutdown (e.g. FastAPI shutdown event or at the end of a script).
    """
    if _backend is not None and not _backend_is_async:
        if hasattr(_backend, "close"):
            _backend.close()

async def teardown_async() -> None:
    """Close the active async backend and release connections.
    
    Call this on application shutdown (e.g. FastAPI shutdown event or at the end of a script).
    """
    if _backend is not None and _backend_is_async:
        if hasattr(_backend, "aclose"):
            await _backend.aclose()

# ---------------------------------------------------------------------------
# Module-level configuration
# ---------------------------------------------------------------------------

#: Hardcoded fallback used only when ``TEMPID_SECRET`` is unset.  Its value is
#: deliberately long and human-readable so it is obviously wrong in logs.
_INSECURE_DEFAULT = b"tempid-insecure-default-do-not-use-in-production"

_warn_lock = threading.Lock()  # DCLP - fires once under concurrency
_warn_issued = False

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DURATION_RE = re.compile(r"^(\d+)([smhd])$")
_UNITS: dict[str, int] = {"s": 1, "m": 60, "h": 3_600, "d": 86_400}

#: Sanity window for decoded timestamps: 2020-01-01 to 2100-01-01 (UTC).
_TS_MIN = 1_577_836_800
_TS_MAX = 4_102_444_800

TOKEN_VERSION = "V2"
TOKEN_PREFIX = f"TEMP-{TOKEN_VERSION}"
_MAX_PAYLOAD_BYTES = 512

# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _warn_once() -> None:
    """Emit the insecure-secret warning exactly once, thread-safely."""
    global _warn_issued
    if _warn_issued:          # Fast path — avoids lock acquisition in steady state.
        return
    with _warn_lock:
        if not _warn_issued:  # Re-check inside the lock (classic DCLP).
            warnings.warn(
                "\n[tempid] TEMPID_SECRET is not set.\n"
                "Anyone who knows the insecure default can forge valid TempIDs.\n"
                "Generate and export a secret before going to production:\n"
                '"$(python -c \'import secrets; print(secrets.token_hex(32))\')"',
                UserWarning,
                stacklevel=2,   # Points to _get_secret() — the nearest useful frame.
            )
            _warn_issued = True


def _get_secret() -> bytes:
    """Return the HMAC signing secret as :class:`bytes`."""
    secret = os.environ.get("TEMPID_SECRET", "")
    if secret:
        return secret.encode()
    _warn_once()
    return _INSECURE_DEFAULT


def _parse_duration(duration: str) -> int:
    """
    Parse a human-readable duration string into a number of seconds.

    Supported suffixes: ``s`` (seconds), ``m`` (minutes), ``h`` (hours),
    ``d`` (days).

    Args:
        duration: A string like ``"30s"``, ``"10m"``, ``"2h"``, or ``"7d"``.

    Returns:
        Equivalent duration in seconds as a positive :class:`int`.

    Raises:
        ValueError: if *duration* does not match the expected pattern.
    """
    match = _DURATION_RE.fullmatch(duration.strip().lower())
    if not match:
        raise ValueError(
            f"Invalid duration {duration!r}. "
            "Expected format: '30s', '10m', '2h', '7d'."
        )
    return int(match.group(1)) * _UNITS[match.group(2)]


# Payload key cache — invalidated when secret changes
_derived_cache: tuple[bytes, bytes] | None = None
_derived_key_lock = threading.Lock()


def _derive_payload_key() -> bytes:
    global _derived_cache
    current_secret = _get_secret()
    
    cache = _derived_cache
    if cache is not None and cache[0] == current_secret:
        return cache[1]
        
    with _derived_key_lock:
        cache = _derived_cache
        if cache is None or cache[0] != current_secret:
            new_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b"tempid-payload-enc-v2",
            ).derive(current_secret)
            _derived_cache = (current_secret, new_key)
            return new_key
        return cache[1]


def _encrypt_payload(data: bytes) -> bytes:
    key = _derive_payload_key()
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, data, None)


def _decrypt_payload(data: bytes) -> bytes:
    if len(data) < 12:
        raise ValueError("Encrypted payload too short (missing nonce).")
    
    key = _derive_payload_key()
    nonce = data[:12]
    encrypted = data[12:]
    return AESGCM(key).decrypt(nonce, encrypted, None)


def _b32_encode_dashed(data: bytes) -> str:
    """Encode bytes to Base32 and insert dashes every 5 characters for aesthetics."""
    b32 = base64.b32encode(data).rstrip(b"=").decode("ascii")
    return "-".join(b32[i : i + 5] for i in range(0, len(b32), 5))


def _b32_decode_dashed(s: str) -> bytes:
    """Remove dashes, restore padding, and decode Base32."""
    clean = s.replace("-", "")
    padding = "=" * (-len(clean) % 8)
    return base64.b32decode(clean + padding)


def _encode_v2(expires_at: int, payload_bytes: bytes | None, max_uses: int = 0) -> str:
    """
    Encode *expires_at* and *payload* into a v2 token string.

    Format: ``TEMP-V2.<header_b32>.<payload_b32>.<signature_b32>``
    Header (11 bytes): version(1) + timestamp(5) + nonce(4) + max_uses(1).
    max_uses=0 means unlimited.
    """
    # Header: 1 + 5 + 4 + 1 = 11 bytes
    ts_bytes = struct.pack(">Q", expires_at)[3:]          # 5 bytes
    nonce_bytes = os.urandom(4)                            # 4 bytes
    max_uses_byte = struct.pack("B", min(max_uses, 255))  # 1 byte; 0 = unlimited
    header_raw = b"\x02" + ts_bytes + nonce_bytes + max_uses_byte
    header_b32 = _b32_encode_dashed(header_raw)

    # Payload: bytes -> zlib -> encrypt -> base32
    if payload_bytes is not None:
        if len(payload_bytes) > _MAX_PAYLOAD_BYTES:
            raise TempIDPayloadTooLargeError(
                f"Payload exceeds {_MAX_PAYLOAD_BYTES} bytes "
                f"(current: {len(payload_bytes)} bytes)."
            )
        payload_compressed = zlib.compress(payload_bytes)
        payload_encrypted = _encrypt_payload(payload_compressed)
        payload_b32 = _b32_encode_dashed(payload_encrypted)
    else:
        payload_b32 = ""

    # Signature: HMAC-SHA256 over "TEMP-V2.{header_b32}.{payload_b32}" (or without payload)
    if payload_b32:
        data = f"{TOKEN_PREFIX}.{header_b32}.{payload_b32}"
    else:
        data = f"{TOKEN_PREFIX}.{header_b32}"
        
    sig_raw = hmac.digest(_get_secret(), data.encode("ascii"), "sha256")[:12]
    sig_b32 = _b32_encode_dashed(sig_raw)

    return f"{data}.{sig_b32}"


def _decode_v2(value: str) -> tuple[int, dict[str, Any] | None, int]:
    """
    Decode and cryptographically verify a v2 token string.

    Returns:
        ``(expires_at, payload_dict_or_none, max_uses)``
    Raises:
        TempIDFormatError, TempIDTamperedError
    """
    parts = value.split(".")
    if len(parts) not in (3, 4) or parts[0] != TOKEN_PREFIX:
        raise TempIDFormatError(f"Invalid {TOKEN_VERSION} token format: {value!r}")

    if len(parts) == 3:
        header_b32 = parts[1]
        payload_b32 = ""
        sig_b32 = parts[2]
        data = f"{TOKEN_PREFIX}.{header_b32}"
    else:
        header_b32 = parts[1]
        payload_b32 = parts[2]
        sig_b32 = parts[3]
        data = f"{TOKEN_PREFIX}.{header_b32}.{payload_b32}"

    # Verify signature first
    sig_expected_raw = hmac.digest(_get_secret(), data.encode("ascii"), "sha256")[:12]
    sig_expected_b32 = _b32_encode_dashed(sig_expected_raw)

    if not hmac.compare_digest(sig_b32, sig_expected_b32):
        raise TempIDTamperedError("Token signature verification failed.")

    # Parse header
    try:
        header_raw = _b32_decode_dashed(header_b32)
        if len(header_raw) not in (10, 11) or header_raw[0] != 2:
            raise TempIDFormatError("Invalid v2 header data.")

        # Unpack 5-byte timestamp
        ts_padded = b"\x00\x00\x00" + header_raw[1:6]
        expires_at = struct.unpack(">Q", ts_padded)[0]
        # Read max_uses from byte 10 — 0 if absent (backward compat with old 10-byte tokens)
        max_uses = header_raw[10] if len(header_raw) == 11 else 0
    except (struct.error, binascii.Error, ValueError) as e:
        raise TempIDFormatError("Malformed v2 header.") from e

    if not (_TS_MIN <= expires_at <= _TS_MAX):
        raise TempIDFormatError("Timestamp out of valid range.")

    # Parse payload
    payload = None
    if payload_b32:
        try:
            payload_raw = _b32_decode_dashed(payload_b32)
            payload_compressed = _decrypt_payload(payload_raw)
            payload_json = zlib.decompress(payload_compressed)
            payload = json.loads(payload_json)
            if not isinstance(payload, dict):
                raise TempIDFormatError("Payload must be a JSON object.")
        except TempIDFormatError:
            raise
        except (ValueError, binascii.Error, zlib.error, json.JSONDecodeError, UnicodeDecodeError, InvalidTag) as e:
            raise TempIDTamperedError("Payload decryption failed - possibly tampered.") from e

    return expires_at, payload, max_uses


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


class TempID:
    """
    A cryptographically signed, self-expiring identifier.

    A :class:`TempID` carries its own expiry timestamp inside the token
    string itself, protected by an HMAC-SHA256 signature.  No database or
    external store is required to verify tokens.

    **Creating a token**::

        tid = TempID.new("15m")
        link = f"https://example.com/reset?token={tid}"

    **Verifying a token**::

        tid = TempID.from_string(request.args["token"])
        if tid.valid():
            do_the_thing()

    Attributes:
        value (str): The token string.
        expires_at (int): Unix timestamp (seconds since epoch) at which this
            token expires.
        payload (dict | None): Attached dictionary data, if any.
    """

    # __slots__ eliminates the per-instance __dict__, reducing memory usage
    # by ~50 bytes per instance — meaningful when tracking many short-lived
    # tokens in a cache or set.
    __slots__ = ("value", "expires_at", "payload", "max_uses", "_callbacks")

    def __init__(
        self, value: str, expires_at: int, payload: dict[str, Any] | None = None,
        max_uses: int = 0,
    ) -> None:
        self.value: str = value
        self.expires_at: int = expires_at
        self.payload: dict[str, Any] | None = payload
        self.max_uses: int = max_uses
        self._callbacks: list[Callable[[], None]] | None = None

    # ------------------------------------------------------------------
    # Constructors
    # ------------------------------------------------------------------

    @classmethod
    def new(
        cls,
        expires_in: str = "10m",
        payload: dict[str, Any] | None = None,
        max_uses: int = 0,
    ) -> "TempID":
        """
        Create a new :class:`TempID` that expires after *expires_in*.

        Args:
            expires_in: Duration string — one of ``"30s"``, ``"10m"``,
                ``"2h"``, or ``"7d"``.  Defaults to ``"10m"``.
            payload: Optional JSON-serializable dictionary to embed in the token.
            max_uses: Maximum number of times this token may be consumed via
                :meth:`use`. ``0`` means unlimited (default). Range: 0–255.

        Returns:
            A freshly minted :class:`TempID` instance.

        Raises:
            ValueError: if *expires_in* is not a valid duration string.
            TempIDPayloadTooLargeError: if payload JSON exceeds 512 bytes.

        Example::

            tid = TempID.new("15m", payload={"user_id": 42})
            print(tid.value)       # "t2...."
            print(tid.remaining()) # "14m 59s"
        """
        payload_bytes = None
        if payload is not None:
            if not isinstance(payload, dict):
                raise TypeError("payload must be a dict")
            try:
                payload_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            except (TypeError, ValueError) as e:
                raise ValueError("payload must be JSON-serializable") from e

        if not isinstance(max_uses, int) or not (0 <= max_uses <= 255):
            raise ValueError("max_uses must be an integer in range 0–255.")

        seconds = _parse_duration(expires_in)
        expires_at = int(time.time()) + seconds
        value = _encode_v2(expires_at, payload_bytes, max_uses)
        return cls(value, expires_at, payload, max_uses)

    @classmethod
    def from_string(cls, value: str) -> "TempID":
        """
        Restore a :class:`TempID` from its string representation.

        Args:
            value: Token string.

        Returns:
            A :class:`TempID` instance.  Call :meth:`valid` or
            :meth:`expired` to check whether it is still active.

        Raises:
            TypeError: if *value* is not a :class:`str`.
            TempIDFormatError: if the token is malformed.
            TempIDTamperedError: if the token signature is invalid.

        Example::

            tid = TempID.from_string(request.args["token"])
            if tid.valid():
                process(tid)
        """
        if not isinstance(value, str):
            raise TypeError(
                f"TempID.from_string() requires a str, got {type(value).__name__!r}."
            )
        
        value = value.strip()
        
        if value.startswith(f"{TOKEN_PREFIX}."):
            expires_at, payload, max_uses = _decode_v2(value)
            return cls(value, expires_at, payload, max_uses)
        
        raise TempIDFormatError(f"Invalid {TOKEN_VERSION} token format: {value!r}")

    @classmethod
    def verify(cls, value: str, check_uses: bool = False) -> "TempID" | None:
        """
        Safe, one-step token verification.
        
        Returns the :class:`TempID` if the token is valid, has not been
        tampered with, and has not yet expired. Returns ``None`` for any failure
        (malformed, tampered, or expired).
        
        If ``check_uses=True``, this will also check the database to ensure the 
        token's ``max_uses`` limit has not been exhausted. It does NOT consume 
        a use.
        
        This is safe from DB-DDoS attacks because it performs the offline
        cryptographic checks *before* ever touching the database.

        Args:
            value: The token string to verify.
            check_uses: If True, query the database to ensure uses remain.

        Returns:
            A valid, unexpired :class:`TempID` instance, or ``None``.
        """
        try:
            tid = cls.from_string(value)
            if not tid.valid():
                return None
            
            if check_uses and tid.max_uses > 0:
                info = tid.uses_info()
                if info["left"] == 0:
                    return None
                    
            return tid
        except (TempIDFormatError, TempIDTamperedError, TypeError):
            return None

    @classmethod
    async def verify_async(cls, value: str, check_uses: bool = False) -> "TempID" | None:
        """
        Safe, one-step token verification (Async version).
        
        Like `verify()`, but designed for use with AsyncBaseBackend.
        
        Requires an AsyncBaseBackend to be configured via `configure()`.
        """
        try:
            tid = cls.from_string(value)
            if not tid.valid():
                return None
            
            if check_uses and tid.max_uses > 0:
                info = await tid.uses_info_async()
                if info["left"] == 0:
                    return None
                    
            return tid
        except (TempIDFormatError, TempIDTamperedError, TypeError):
            return None

    # ------------------------------------------------------------------
    # Use-count methods (requires a backend configured via configure())
    # ------------------------------------------------------------------

    def use(self) -> bool:
        """Consume one use of this token.

        Returns ``True`` if the use was allowed, ``False`` if the token has
        reached its ``max_uses`` limit.

        For unlimited tokens (``max_uses=0``) this always returns ``True``
        without touching the backend.

        Example::

            tid = TempID.verify(token)
            if tid and not tid.use():
                abort(429)  # max uses reached
        """
        if _backend_is_async:
            raise RuntimeError("Configured backend is async. Use 'await tid.use_async()' instead.")
        if self.expired():
            return False
        if self.max_uses == 0:
            return True  # unlimited — no backend call needed
        token_id = self.value.split(".")[-1]  # signature is the unique token ID
        from typing import cast
        sync_backend = cast(BaseBackend, _backend)
        return sync_backend.increment_use(token_id, self.max_uses, self.expires_at)

    async def use_async(self) -> bool:
        """Consume one use of this token (Async version)."""
        if not _backend_is_async:
            raise RuntimeError("Configured backend is sync. Use 'tid.use()' instead.")
        if self.expired():
            return False
        if self.max_uses == 0:
            return True
        token_id = self.value.split(".")[-1]
        from typing import cast
        async_backend = cast(AsyncBaseBackend, _backend)
        return await async_backend.increment_use(token_id, self.max_uses, self.expires_at)

    def uses_info(self) -> dict[str, int | None]:
        """Return use-count information in a single backend call."""
        if _backend_is_async:
            raise RuntimeError("Configured backend is async. Use 'await tid.uses_info_async()' instead.")
        if self.max_uses == 0:
            return {"total": None, "used": None, "left": None}
        token_id = self.value.split(".")[-1]
        from typing import cast
        sync_backend = cast(BaseBackend, _backend)
        used = sync_backend.use_count(token_id)
        return {
            "total": self.max_uses,
            "used": used,
            "left": max(0, self.max_uses - used),
        }

    async def uses_info_async(self) -> dict[str, int | None]:
        """Return use-count information (Async version)."""
        if not _backend_is_async:
            raise RuntimeError("Configured backend is sync. Use 'tid.uses_info()' instead.")
        if self.max_uses == 0:
            return {"total": None, "used": None, "left": None}
        token_id = self.value.split(".")[-1]
        from typing import cast
        async_backend = cast(AsyncBaseBackend, _backend)
        used = await async_backend.use_count(token_id)
        return {
            "total": self.max_uses,
            "used": used,
            "left": max(0, self.max_uses - used),
        }

    # ------------------------------------------------------------------
    # State checks
    # ------------------------------------------------------------------

    def valid(self) -> bool:
        """
        Return ``True`` if this token has **not** yet expired.

        Side effect: when the token transitions from valid to expired, all
        callbacks registered via :meth:`on_expire` are invoked exactly once
        and then cleared.  Subsequent calls to :meth:`valid` after expiry
        are side-effect-free.
        """
        if int(time.time()) < self.expires_at:
            return True
        self._fire_callbacks()
        return False

    def expired(self) -> bool:
        """
        Return ``True`` if this token **has** expired.

        This is the logical complement of :meth:`valid` and shares the same
        callback-firing behaviour.
        """
        return not self.valid()

    def remaining(self) -> str:
        """
        Return a human-readable description of the time remaining until expiry.

        Returns:
            One of the following forms, depending on how much time is left:

            - ``"expired"``  — token has already expired
            - ``"42s"``      — less than one minute remaining
            - ``"9m 45s"``   — less than one hour remaining
            - ``"1h 20m"``   — less than one day remaining
            - ``"6d 23h"``   — one or more days remaining
        """
        secs = max(0, int(self.expires_at - time.time()))
        if secs == 0:
            return "expired"
        if secs < 60:
            return f"{secs}s"
        if secs < 3_600:
            return f"{secs // 60}m {secs % 60}s"
        if secs < 86_400:
            return f"{secs // 3_600}h {(secs % 3_600) // 60}m"
        return f"{secs // 86_400}d {(secs % 86_400) // 3_600}h"

    # ------------------------------------------------------------------
    # Callbacks
    # ------------------------------------------------------------------

    def on_expire(self, callback: Callable[[], None]) -> "TempID":
        """
        Register *callback* to be called once when this token expires.

        Callbacks are invoked on the first :meth:`valid` call that occurs
        after the token's expiry time.  Exceptions raised inside a callback
        are silently suppressed so they cannot disrupt the caller.

        Args:
            callback: A zero-argument callable.

        Returns:
            ``self``, enabling fluent chaining::

                tid.on_expire(cleanup_session).on_expire(log_expiry)
        """
        if self._callbacks is None:
            self._callbacks = []
        self._callbacks.append(callback)
        return self

    def _fire_callbacks(self) -> None:
        """
        Invoke all registered expiry callbacks and clear the list.

        This method is idempotent: calling it a second time (after the list
        has been cleared) is a safe no-op.  It should only be called from
        :meth:`valid` to ensure callbacks fire at the right moment.
        """
        if not self._callbacks:
            return
        for cb in self._callbacks:
            try:
                cb()
            except Exception:  # noqa: BLE001
                pass
        self._callbacks = None

    # ------------------------------------------------------------------
    # Dunder methods
    # ------------------------------------------------------------------

    def __str__(self) -> str:
        return self.value

    def __repr__(self) -> str:
        # Intentionally avoids calling self.valid() here.
        # Calling valid() would fire on_expire callbacks as a side-effect of
        # merely printing or inspecting the object in a REPL — surprising and
        # wrong.  We compute the status independently without side-effects.
        is_valid = int(time.time()) < self.expires_at
        status = "valid" if is_valid else "expired"
        return f"TempID('{self.value}', {status}, remaining={self.remaining()})"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, TempID):
            return self.value == other.value
        other_str = str(other).strip()
        return self.value == other_str

    def __hash__(self) -> int:
        return hash(self.value)
