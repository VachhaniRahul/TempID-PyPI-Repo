import os
import zlib
import json
import struct
import pytest
import hmac

from tempid import TempID, configure, MemoryBackend
import tempid.core as core
from tempid.exceptions import TempIDFormatError, TempIDTamperedError, TempIDPayloadTooLargeError


def fresh_memory():
    backend = MemoryBackend()
    configure(store=backend)
    return backend


def test_payload_roundtrip():
    payload = {"user_id": 42, "role": "admin"}
    tid = TempID.new("1h", payload=payload)
    assert tid.value.startswith("TEMP-V2.")
    assert tid.payload == payload

    restored = TempID.from_string(tid.value)
    assert restored.payload == payload


def test_payload_empty_is_none():
    tid = TempID.new("1h")
    assert tid.payload is None

    restored = TempID.from_string(tid.value)
    assert restored.payload is None


def test_payload_tampered_raises():
    tid = TempID.new("1h", payload={"test": 1})
    parts = tid.value.split(".")

    # Tamper with payload
    parts[2] = parts[2][:-1] + ("A" if parts[2][-1] != "A" else "B")
    tampered = ".".join(parts)

    with pytest.raises(TempIDTamperedError):
        TempID.from_string(tampered)


def test_payload_too_large_raises():
    large_payload = {"data": "x" * 600}
    with pytest.raises(TempIDPayloadTooLargeError):
        TempID.new("1h", payload=large_payload)


def test_max_uses_not_in_payload():
    """max_uses must be encoded in the header — not visible in tid.payload."""
    fresh_memory()
    tid = TempID.new("10m", payload={"user_id": 42}, max_uses=3)
    assert "__mu" not in (tid.payload or {})
    assert tid.payload == {"user_id": 42}


def test_decrypt_payload_too_short():
    """Test short payload decryption."""
    with pytest.raises(ValueError, match="Encrypted payload too short"):
        core._decrypt_payload(b"short_bytes")


def test_payload_must_be_dict_creation():
    """Test TempID.new() raises TypeError if payload is not a dict."""
    with pytest.raises(TypeError, match="payload must be a dict"):
        TempID.new("10m", payload=["a", "list", "instead", "of", "dict"])


def test_payload_must_be_serializable_creation():
    """Test TempID.new() raises ValueError if payload cannot be JSON serialized."""
    with pytest.raises(ValueError, match="payload must be JSON-serializable"):
        TempID.new("10m", payload={"func": lambda: None})


def test_payload_must_be_dict_decryption():
    """Test TempID.from_string() raises error if decrypted payload is not a dict."""
    # Manually craft a token where payload is a JSON array
    payload_json = json.dumps(["a", "list"]).encode("utf-8")
    payload_compressed = zlib.compress(payload_json)
    payload_encrypted = core._encrypt_payload(payload_compressed)
    payload_b32 = core._b32_encode_dashed(payload_encrypted)

    expires_at = 2000000000
    ts_bytes = struct.pack(">Q", expires_at)[3:]
    nonce_bytes = os.urandom(4)
    header_raw = b"\x02" + ts_bytes + nonce_bytes + b"\x00"
    header_b32 = core._b32_encode_dashed(header_raw)

    data = f"{core.TOKEN_PREFIX}.{header_b32}.{payload_b32}"
    sig_raw = hmac.digest(core._get_secret(), data.encode("ascii"), "sha256")[:12]
    sig_b32 = core._b32_encode_dashed(sig_raw)

    bad_token = f"{data}.{sig_b32}"

    with pytest.raises(TempIDFormatError, match="Payload must be a JSON object"):
        TempID.from_string(bad_token)


def test_payload_decryption_tampered_fails():
    """Test that a tampered payload throws TempIDTamperedError on bad JSON/zlib."""
    # Craft a token with a payload that decrypts correctly but is garbage zlib data
    # (By creating valid AEAD tag but garbage plaintext)

    # Create encrypted garbage
    key = core._derive_payload_key()
    nonce = os.urandom(12)
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    garbage_encrypted = nonce + AESGCM(key).encrypt(nonce, b"not zlib data", None)

    payload_b32 = core._b32_encode_dashed(garbage_encrypted)

    expires_at = 2000000000
    ts_bytes = struct.pack(">Q", expires_at)[3:]
    nonce_bytes = os.urandom(4)
    header_raw = b"\x02" + ts_bytes + nonce_bytes + b"\x00"
    header_b32 = core._b32_encode_dashed(header_raw)

    data = f"{core.TOKEN_PREFIX}.{header_b32}.{payload_b32}"
    sig_raw = hmac.digest(core._get_secret(), data.encode("ascii"), "sha256")[:12]
    sig_b32 = core._b32_encode_dashed(sig_raw)

    bad_token = f"{data}.{sig_b32}"

    with pytest.raises(TempIDTamperedError, match="Payload decryption failed"):
        TempID.from_string(bad_token)
