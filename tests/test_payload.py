import os
import time

import pytest

from tempid import (
    TempID,
    TempIDFormatError,
    TempIDPayloadTooLargeError,
    TempIDTamperedError,
)

# Ensure secret is set for tests
os.environ["TEMPID_SECRET"] = "test-secret-payload"


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


def test_verify_returns_none_for_invalid():
    assert TempID.verify("invalid-token") is None
    assert TempID.verify("TEMP-V2.invalid.invalid.invalid") is None


def test_verify_returns_none_for_expired():
    # Mock time to create an expired token
    original_time = time.time
    try:
        time.time = lambda: original_time() - 3600  # 1 hour ago
        tid = TempID.new("10m")
    finally:
        time.time = original_time

    assert TempID.verify(tid.value) is None


def test_verify_returns_tempid_for_valid():
    tid = TempID.new("10m", payload={"ok": True})
    result = TempID.verify(tid.value)
    assert isinstance(result, TempID)
    assert result.payload == {"ok": True}


def test_v1_token_still_parseable():
    # Encoded using v1 engine logic, should still parse properly
    # Using a known valid v1 token structure (we need to be careful as v1 uses the global secret)
    # We will just verify that TempID.verify handles v1 format without crashing
    
    # A valid v1 token requires secret matching, so we generate one directly
    # Wait, v1 _encode is gone, wait no it's not.
    # Actually, TempID.new() generates v2 now, but we can call _encode(expires_at) to generate a v1
    from tempid.core import _encode
    expires_at = int(time.time()) + 600
    v1_token = _encode(expires_at)
    
    restored = TempID.from_string(v1_token)
    assert restored.expires_at == expires_at
    assert restored.payload is None

    result = TempID.verify(v1_token)
    assert result is not None
    assert result.expires_at == expires_at


def test_exception_types_are_correct():
    with pytest.raises(TempIDFormatError):
        TempID.from_string("TEMP-V2.short")

    with pytest.raises(TempIDTamperedError):
        TempID.from_string("TEMP-V2.notbase64!.notbase64!.notbase64!")

    with pytest.raises(TypeError):
        TempID.from_string(123)  # type: ignore
