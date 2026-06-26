"""
tempid.core — Secure, self-expiring token engine.

Token format (v1)
-----------------
A token is a 22 hex-character string formatted as ``XXXXXXXX-XXXXXX-XXXXXXXX``
(groups of 8, 6, and 8; separated by dashes).  All characters are uppercase.

Layout (dashes stripped, 22 chars):
  ``[0:8]``   — encrypted timestamp  (32-bit XOR-masked unix expiry time)
  ``[8:14]``  — random nonce         (24-bit, ensures uniqueness per second)
  ``[14:22]`` — HMAC-SHA256 signature (32-bit, tamper detection)

Security model
--------------
The HMAC signature (keyed with ``TEMPID_SECRET``) covers the header + nonce,
so any mutation of the token — including the expiry timestamp — is detected.
The timestamp is additionally XOR-masked with a secret-derived constant so
the raw expiry is not readable from the token by a third party.

Set the secret via the environment before starting your application::

    export TEMPID_SECRET="$(python -c 'import secrets; print(secrets.token_hex(32))')"

If the secret is not set, a :class:`UserWarning` is issued once and an
insecure hardcoded fallback is used.  **Never deploy to production without
setting the secret.**
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import struct
import threading
import time
import warnings
import zlib
from typing import Any, Callable

from .exceptions import (
    TempIDExpiredError,
    TempIDFormatError,
    TempIDPayloadTooLargeError,
    TempIDTamperedError,
)

# ---------------------------------------------------------------------------
# Module-level configuration
# ---------------------------------------------------------------------------

#: Signing secret read once at import time.  Mutating this after import has
#: no effect unless :func:`_get_secret` is also patched — intentional, because
#: runtime secret rotation requires a token-format version bump (v2).
_SECRET: str = os.environ.get("TEMPID_SECRET", "")

#: Hardcoded fallback used only when ``TEMPID_SECRET`` is unset.  Its value is
#: deliberately long and human-readable so it is obviously wrong in logs.
_INSECURE_DEFAULT = b"tempid-insecure-default-do-not-use-in-production"

# Thread-safe gate so the "secret not set" warning fires at most once per
# process, even under concurrent request handling (e.g. Gunicorn workers).
_warn_lock   = threading.Lock()
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
    """
    Emit the insecure-default :class:`UserWarning` exactly once, thread-safely.

    Uses a ``threading.Lock`` double-checked locking pattern so that in a
    multithreaded server (Gunicorn, Uvicorn, etc.) only one thread ever
    emits the warning, even if many requests arrive simultaneously.
    """
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
    """
    Return the HMAC signing secret as :class:`bytes`.

    Resolution order:

    1. ``TEMPID_SECRET`` environment variable (production path — no warning).
    2. :data:`_INSECURE_DEFAULT` (development fallback — emits warning once).

    The secret is read at module import time (stored in :data:`_SECRET`) so
    this function is effectively a constant-time lookup in the hot path.
    """
    if _SECRET:
        return _SECRET.encode()
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


def _sign(payload: str) -> str:
    """
    Return a 16-character lowercase hex HMAC-SHA256 digest of *payload*.

    The digest is keyed with the configured secret (see :func:`_get_secret`).
    Callers slice to the length they need rather than this function deciding
    the output length, keeping the function general and testable.
    """
    return hmac.new(_get_secret(), payload.encode(), hashlib.sha256).hexdigest()[:16]


def _encrypt_ts(expires_at: int) -> str:
    """
    XOR-encrypt *expires_at* with a deterministic secret-derived mask.

    The mask is stable for a given secret (derived from ``_sign("ts-mask-v1")``),
    so encryption is fully reversible without storing any state.  The goal is
    to prevent the expiry time from being read directly out of the token by a
    curious third party — it is **not** intended to provide confidentiality
    against an attacker who knows the secret.

    Args:
        expires_at: Unix timestamp (seconds since epoch).

    Returns:
        8-character lowercase hex string representing the encrypted value.
    """
    mask = int(_sign("ts-mask-v1")[:8], 16)
    return f"{(expires_at ^ mask):08x}"


def _decrypt_ts(encrypted_hex: str) -> int:
    """
    Reverse of :func:`_encrypt_ts`.

    Args:
        encrypted_hex: 8-character hex string produced by :func:`_encrypt_ts`.

    Returns:
        Original unix timestamp as an :class:`int`.
    """
    mask = int(_sign("ts-mask-v1")[:8], 16)
    return int(encrypted_hex, 16) ^ mask


def _encode(expires_at: int) -> str:
    """
    Encode *expires_at* into a v1 token string.

    Token layout (dashes stripped)::

        enc_ts (8) + nonce (6) + sig (8)  =  22 hex chars

    Formatted with dashes as ``XXXXXXXX-XXXXXX-XXXXXXXX``.

    Args:
        expires_at: Unix timestamp at which the token should expire.

    Returns:
        A 26-character uppercase token string (22 hex chars + 2 dashes).
    """
    enc_ts = _encrypt_ts(expires_at)   # 8 hex chars — encrypted expiry
    nonce  = os.urandom(3).hex()       # 6 hex chars — prevents collisions
    header = enc_ts + nonce            # 14 chars
    sig    = _sign(header)[:8]         # 8 hex chars — tamper-proof signature
    raw    = (header + sig).upper()    # 22 chars total, uppercase
    return f"{raw[:8]}-{raw[8:14]}-{raw[14:]}"


def _decode(value: str) -> tuple[int, bool]:
    """
    Decode and cryptographically verify a v1 token string.

    All failures (wrong length, tampered signature, out-of-range timestamp,
    or any unexpected exception from untrusted input) are collapsed into the
    ``(0, False)`` sentinel so callers never need defensive try/except.

    Args:
        value: Raw token string (any case, dashes optional).

    Returns:
        ``(expires_at, True)``  on success.
        ``(0,          False)`` on any failure.
    """
    try:
        clean = value.replace("-", "").lower()
        if len(clean) != 22:
            return 0, False

        header       = clean[:14]
        sig_received = clean[14:]
        sig_expected = _sign(header)[:8]

        # hmac.compare_digest is timing-safe — prevents signature-length
        # timing oracles even though our signatures are hex strings.
        if not hmac.compare_digest(sig_received, sig_expected):
            return 0, False

        expires_at = _decrypt_ts(header[:8])

        # Reject timestamps outside the plausible range (year 2020–2100).
        # This catches random garbage that happens to pass the HMAC check
        # (statistically impossible, but good defence-in-depth).
        if not (_TS_MIN <= expires_at <= _TS_MAX):
            return 0, False

        return expires_at, True

    except Exception:  # noqa: BLE001 — intentional broad catch for untrusted input
        return 0, False


def _encrypt_payload(data: bytes) -> bytes:
    """
    Encrypt data using a CTR-mode stream cipher with HMAC-SHA256.
    Returns: 16-byte IV + encrypted data.
    """
    iv = os.urandom(16)
    keystream = bytearray()
    counter = 0
    secret = _get_secret()
    
    # Generate enough keystream bytes
    while len(keystream) < len(data):
        # PRF: HMAC-SHA256(secret, IV + counter)
        block_input = iv + struct.pack(">I", counter)
        keystream.extend(hmac.new(secret, block_input, hashlib.sha256).digest())
        counter += 1
        
    encrypted = bytes(a ^ b for a, b in zip(data, keystream))
    return iv + encrypted


def _decrypt_payload(data: bytes) -> bytes:
    """
    Decrypt data encrypted by _encrypt_payload.
    """
    if len(data) < 16:
        raise ValueError("Encrypted payload too short (missing IV).")
    
    iv = data[:16]
    encrypted = data[16:]
    keystream = bytearray()
    counter = 0
    secret = _get_secret()
    
    while len(keystream) < len(encrypted):
        block_input = iv + struct.pack(">I", counter)
        keystream.extend(hmac.new(secret, block_input, hashlib.sha256).digest())
        counter += 1
        
    return bytes(a ^ b for a, b in zip(encrypted, keystream))


def _b32_encode_dashed(data: bytes) -> str:
    """Encode bytes to Base32 and insert dashes every 5 characters for aesthetics."""
    b32 = base64.b32encode(data).rstrip(b"=").decode("ascii")
    return "-".join(b32[i : i + 5] for i in range(0, len(b32), 5))


def _b32_decode_dashed(s: str) -> bytes:
    """Remove dashes, restore padding, and decode Base32."""
    clean = s.replace("-", "")
    padding = "=" * (-len(clean) % 8)
    return base64.b32decode(clean + padding)


def _encode_v2(expires_at: int, payload: dict[str, Any] | None) -> str:
    """
    Encode *expires_at* and *payload* into a v2 token string.

    Format: `TEMP-V2.<header_b32>.<payload_b32>.<signature_b32>`
    """
    # Header: version(1 byte, value=2) + timestamp(5 bytes) + nonce(4 bytes) = 10 bytes
    ts_bytes = struct.pack(">Q", expires_at)[3:]  # Take last 5 bytes of 64-bit int
    nonce_bytes = os.urandom(4)
    header_raw = b"\x02" + ts_bytes + nonce_bytes
    header_b32 = _b32_encode_dashed(header_raw)

    # Payload: json -> zlib -> encrypt -> base32
    if payload:
        payload_json = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        if len(payload_json) > _MAX_PAYLOAD_BYTES:
            raise TempIDPayloadTooLargeError(
                f"Payload exceeds {_MAX_PAYLOAD_BYTES} bytes "
                f"(current: {len(payload_json)} bytes)."
            )
        payload_compressed = zlib.compress(payload_json)
        payload_encrypted = _encrypt_payload(payload_compressed)
        payload_b32 = _b32_encode_dashed(payload_encrypted)
    else:
        payload_b32 = ""

    # Signature: HMAC-SHA256 over "TEMP-V2.{header_b32}.{payload_b32}" (or without payload)
    if payload_b32:
        data = f"{TOKEN_PREFIX}.{header_b32}.{payload_b32}"
    else:
        data = f"{TOKEN_PREFIX}.{header_b32}"
        
    sig_raw = hmac.new(_get_secret(), data.encode("ascii"), hashlib.sha256).digest()[:12]
    sig_b32 = _b32_encode_dashed(sig_raw)

    return f"{data}.{sig_b32}"


def _decode_v2(value: str) -> tuple[int, dict[str, Any] | None]:
    """
    Decode and cryptographically verify a v2 token string.

    Returns:
        (expires_at, payload_dict_or_none)
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
    sig_expected_raw = hmac.new(_get_secret(), data.encode("ascii"), hashlib.sha256).digest()[:12]
    sig_expected_b32 = _b32_encode_dashed(sig_expected_raw)

    if not hmac.compare_digest(sig_b32, sig_expected_b32):
        raise TempIDTamperedError("Token signature verification failed.")

    # Parse header
    try:
        header_raw = _b32_decode_dashed(header_b32)
        if len(header_raw) != 10 or header_raw[0] != 2:
            raise TempIDFormatError("Invalid v2 header data.")
        
        # Unpack 5-byte timestamp
        ts_padded = b"\x00\x00\x00" + header_raw[1:6]
        expires_at = struct.unpack(">Q", ts_padded)[0]
    except Exception as e:
        raise TempIDFormatError("Malformed v2 header.") from e

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
        except Exception as e:
            raise TempIDFormatError("Malformed or undecryptable v2 payload.") from e

    return expires_at, payload


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
    __slots__ = ("value", "expires_at", "payload", "_callbacks")

    def __init__(
        self, value: str, expires_at: int, payload: dict[str, Any] | None = None
    ) -> None:
        self.value: str = value
        self.expires_at: int = expires_at
        self.payload: dict[str, Any] | None = payload
        self._callbacks: list[Callable[[], None]] = []

    # ------------------------------------------------------------------
    # Constructors
    # ------------------------------------------------------------------

    @classmethod
    def new(cls, expires_in: str = "10m", payload: dict[str, Any] | None = None) -> "TempID":
        """
        Create a new :class:`TempID` that expires after *expires_in*.

        Args:
            expires_in: Duration string — one of ``"30s"``, ``"10m"``,
                ``"2h"``, or ``"7d"``.  Defaults to ``"10m"``.
            payload: Optional JSON-serializable dictionary to embed in the token.

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
        seconds    = _parse_duration(expires_in)
        expires_at = int(time.time()) + seconds
        value = _encode_v2(expires_at, payload)
        return cls(value, expires_at, payload)

    @classmethod
    def from_string(cls, value: str) -> "TempID":
        """
        Restore a :class:`TempID` from its string representation.

        Accepts both v1 and v2 tokens.

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
            expires_at, payload = _decode_v2(value)
            return cls(value, expires_at, payload)
        
        # Fallback to v1 token
        expires_at, ok = _decode(value)
        if not ok:
            raise TempIDFormatError(f"Invalid or tampered TempID: {value!r}.")
        return cls(value.upper(), expires_at, None)

    @classmethod
    def verify(cls, value: str) -> "TempID" | None:
        """
        Safe, one-step token verification.
        
        Returns the :class:`TempID` if the token is valid, has not been
        tampered with, and has not yet expired. Returns ``None`` for any failure
        (malformed, tampered, or expired).
        
        This is the recommended way to consume tokens from untrusted sources
        (like URLs or API requests) because it collapses all edge cases into
        a simple ``if`` check.

        Args:
            value: The token string to verify.

        Returns:
            A valid, unexpired :class:`TempID` instance, or ``None``.
        """
        try:
            tid = cls.from_string(value)
            if tid.valid():
                return tid
            return None
        except Exception:
            return None

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
        self._callbacks.clear()

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
        status   = "valid" if is_valid else "expired"
        return f"TempID('{self.value}', {status}, remaining={self.remaining()})"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, TempID):
            return self.value == other.value
        other_str = str(other).strip()
        if self.value.startswith(f"{TOKEN_PREFIX}."):
            return self.value == other_str
        return self.value == other_str.upper()

    def __hash__(self) -> int:
        return hash(self.value)
