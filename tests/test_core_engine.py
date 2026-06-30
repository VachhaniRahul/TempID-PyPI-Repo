import os
import zlib
import json
import base64
import struct
import pytest
from unittest import mock
import warnings
import hmac
import re
import tempfile
import time

from tempid import TempID, configure, MemoryBackend, SQLiteBackend
import tempid.core as core
from tempid.exceptions import TempIDFormatError, TempIDTamperedError, TempIDPayloadTooLargeError

def fresh_memory():
    backend = MemoryBackend()
    configure(store=backend)
    return backend

def test_create_returns_tempid():
    tid = TempID.new("10m")
    assert isinstance(tid, TempID)
    assert tid.value

def test_valid_on_creation():
    assert TempID.new("10m").valid() is True

def test_expired_on_creation():
    assert TempID.new("10m").expired() is False

def test_value_is_v2_format():
    tid = TempID.new("10m")
    assert tid.value.startswith("TEMP-V2.")

def test_value_format():
    import re
    tid = TempID.new("10m")
    assert re.match(r"^TEMP-V2\.[A-Z2-7-]+\.[A-Z2-7-]+$", tid.value)

def test_seconds():
    tid = TempID.new("30s")
    assert tid.valid()
    assert "s" in tid.remaining()

def test_minutes():
    assert TempID.new("5m").valid()

def test_hours():
    assert TempID.new("2h").valid()

def test_days():
    assert TempID.new("7d").valid()

def test_invalid_duration():
    with pytest.raises(ValueError):
        TempID.new("10x")

def test_invalid_duration_no_unit():
    with pytest.raises(ValueError):
        TempID.new("100")

def test_expires_correctly():
    tid = TempID.new("1s")
    assert tid.valid()
    time.sleep(2)
    assert tid.expired()
    assert not tid.valid()

def test_remaining_after_expiry():
    tid = TempID.new("1s")
    time.sleep(2)
    assert tid.remaining() == "expired"

def test_remaining_minutes_format():
    tid = TempID.new("10m")
    r = tid.remaining()
    assert "m" in r

def test_remaining_hours_format():
    tid = TempID.new("2h")
    r = tid.remaining()
    assert "h" in r

def test_remaining_days_format():
    tid = TempID.new("2d")
    r = tid.remaining()
    assert "d" in r

def test_from_string_roundtrip():
    tid = TempID.new("10m")
    restored = TempID.from_string(tid.value)
    assert restored.valid()
    assert restored.value == tid.value

def test_from_string_invalid_raises():
    from tempid import TempIDFormatError
    with pytest.raises(TempIDFormatError):
        TempID.from_string("INVALID-STRING-HERE")

def test_from_string_wrong_type_raises():
    with pytest.raises(TypeError):
        TempID.from_string(12345)

def test_from_string_expired_but_parseable():
    tid = TempID.new("1s")
    time.sleep(2)
    restored = TempID.from_string(tid.value)
    assert restored.expired()

def test_two_ids_are_different():
    a = TempID.new("10m")
    b = TempID.new("10m")
    assert a.value != b.value

def test_hundred_ids_are_unique():
    ids = {TempID.new("10m").value for _ in range(100)}
    assert len(ids) == 100

def test_on_expire_callback_fires():
    fired = []
    tid = TempID.new("1s")
    tid.on_expire(lambda: fired.append(1))
    time.sleep(2)
    tid.valid()
    assert fired == [1]

def test_callback_fires_only_once():
    fired = []
    tid = TempID.new("1s")
    tid.on_expire(lambda: fired.append(1))
    time.sleep(2)
    tid.valid()
    tid.valid()
    assert len(fired) == 1

def test_multiple_callbacks():
    results = []
    tid = TempID.new("1s")
    tid.on_expire(lambda: results.append("a"))
    tid.on_expire(lambda: results.append("b"))
    time.sleep(2)
    tid.valid()
    assert sorted(results) == ["a", "b"]

def test_callback_not_fired_if_still_valid():
    fired = []
    tid = TempID.new("10m")
    tid.on_expire(lambda: fired.append(1))
    tid.valid()
    assert fired == []

def test_equality_same_value():
    tid = TempID.new("10m")
    restored = TempID.from_string(tid.value)
    assert tid == restored

def test_equality_with_string():
    tid = TempID.new("10m")
    assert tid == tid.value

def test_hashable():
    tid = TempID.new("10m")
    s = {tid}
    assert tid in s

def test_str_returns_value():
    tid = TempID.new("10m")
    assert str(tid) == tid.value

def test_repr_contains_status():
    tid = TempID.new("10m")
    assert "valid" in repr(tid)

def test_repr_expired():
    tid = TempID.new("1s")
    time.sleep(2)
    tid.valid()
    assert "expired" in repr(tid)

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

def test_exception_types_are_correct():
    with pytest.raises(TempIDFormatError):
        TempID.from_string("TEMP-V2.short")

    with pytest.raises(TempIDTamperedError):
        TempID.from_string("TEMP-V2.notbase64!.notbase64!.notbase64!")

    with pytest.raises(TypeError):
        TempID.from_string(123)

def test_verify_does_not_increment():
    """verify() must NOT consume a use — only use() does."""
    fresh_memory()
    tid = TempID.new("10m", max_uses=1)
    TempID.verify(tid.value)  # call verify many times — should not consume
    TempID.verify(tid.value)
    TempID.verify(tid.value)
    restored = TempID.from_string(tid.value)
    assert restored.use() is True   # still 1 use left
    assert restored.use() is False

def test_string_equality_fallback():
    """Test __eq__ method against a string."""
    tid = TempID.new("10m")
    token_str = tid.value
    
    # Compare with identical string
    assert tid == token_str
    
    # Compare with different string
    assert tid != "TEMP-V2.NOT-MY-TOKEN"
    
    # Compare with non-string/non-TempID type
    assert tid != 12345

def test_use_when_expired():
    """Test that use() returns False immediately if the token is expired."""
    tid = TempID.new("10m")
    tid.expires_at = 0  # Force it to be expired
    assert tid.use() is False

