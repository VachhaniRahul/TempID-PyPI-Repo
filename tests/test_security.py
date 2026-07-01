import os
import struct
import pytest
from unittest import mock
import warnings
import hmac

from tempid import TempID, configure, MemoryBackend
import tempid.core as core
from tempid.exceptions import TempIDFormatError


def fresh_memory():
    backend = MemoryBackend()
    configure(store=backend)
    return backend


def test_tampered_last_char():
    from tempid import TempIDError

    tid = TempID.new("10m")
    last = tid.value[-1]
    tampered = tid.value[:-1] + ("A" if last != "A" else "B")
    with pytest.raises(TempIDError):
        TempID.from_string(tampered)


def test_tampered_middle():
    from tempid import TempIDError

    tid = TempID.new("10m")
    chars = list(tid.value)
    idx = 10
    chars[idx] = "A" if chars[idx] != "A" else "B"
    with pytest.raises(TempIDError):
        TempID.from_string("".join(chars))


def test_cannot_extend_expiry():
    from tempid import TempIDError

    tid = TempID.new("1s")
    parts = tid.value.split(".")
    # Tamper with the header
    parts[1] = parts[1][:-1] + ("A" if parts[1][-1] != "A" else "B")
    fake = ".".join(parts)
    with pytest.raises(TempIDError):
        TempID.from_string(fake)


def test_insecure_secret_warning():
    """Test that missing TEMPID_SECRET issues a warning and uses fallback."""
    # Reset the global warn flag so we can test it
    core._warn_issued = False
    with mock.patch.dict(os.environ, clear=True):
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            secret = core._get_secret()

            assert len(w) == 1
            assert issubclass(w[-1].category, UserWarning)
            assert "TEMPID_SECRET is not set" in str(w[-1].message)
            assert secret == core._INSECURE_DEFAULT

            # Second call should not issue a warning
            core._get_secret()
            assert len(w) == 1


def test_invalid_header_length_and_prefix():
    """Test header with invalid length or wrong prefix byte."""
    # Generate a valid token
    tid = TempID.new("10m")
    parts = tid.value.split(".")

    # Modify header (make it 9 bytes instead of 10/11)
    bad_header_raw = b"\x02" + b"A" * 8
    bad_header_b32 = core._b32_encode_dashed(bad_header_raw)
    data1 = f"{parts[0]}.{bad_header_b32}.{parts[2]}"
    sig_raw1 = hmac.digest(core._get_secret(), data1.encode("ascii"), "sha256")[:12]
    sig_b321 = core._b32_encode_dashed(sig_raw1)
    bad_token = f"{data1}.{sig_b321}"

    with pytest.raises(TempIDFormatError, match="Invalid v2 header data"):
        TempID.from_string(bad_token)

    # Modify header prefix (not \x02)
    bad_header_raw2 = b"\x03" + b"A" * 10
    bad_header_b322 = core._b32_encode_dashed(bad_header_raw2)
    data2 = f"{parts[0]}.{bad_header_b322}.{parts[2]}"
    sig_raw2 = hmac.digest(core._get_secret(), data2.encode("ascii"), "sha256")[:12]
    sig_b322 = core._b32_encode_dashed(sig_raw2)
    bad_token2 = f"{data2}.{sig_b322}"

    with pytest.raises(TempIDFormatError, match="Invalid v2 header data"):
        TempID.from_string(bad_token2)


def test_malformed_header_unpack():
    """Test header that causes struct unpack to fail."""
    # This targets the except (struct.error, binascii.Error, ValueError) block
    tid = TempID.new("10m")
    parts = tid.value.split(".")

    # We provide an invalid base32 string for the header
    bad_header_b32 = "INVALID-BASE32-CHARS-!@#$"
    data = f"{parts[0]}.{bad_header_b32}.{parts[2]}"
    sig_raw = hmac.digest(core._get_secret(), data.encode("ascii"), "sha256")[:12]
    sig_b32 = core._b32_encode_dashed(sig_raw)
    bad_token = f"{data}.{sig_b32}"

    with pytest.raises(TempIDFormatError, match="Malformed v2 header"):
        TempID.from_string(bad_token)


def test_timestamp_out_of_bounds():
    """Test timestamp outside the _TS_MIN and _TS_MAX sanity window."""
    # Year 2150 (beyond _TS_MAX)
    expires_at = 4733510400

    # Encode token manually
    ts_bytes = struct.pack(">Q", expires_at)[3:]
    nonce_bytes = os.urandom(4)
    header_raw = b"\x02" + ts_bytes + nonce_bytes + b"\x00"
    header_b32 = core._b32_encode_dashed(header_raw)

    data = f"{core.TOKEN_PREFIX}.{header_b32}"
    sig_raw = hmac.digest(core._get_secret(), data.encode("ascii"), "sha256")[:12]
    sig_b32 = core._b32_encode_dashed(sig_raw)

    bad_token = f"{data}.{sig_b32}"

    with pytest.raises(TempIDFormatError, match="Timestamp out of valid range"):
        TempID.from_string(bad_token)


def test_callback_exception_is_suppressed():
    """Test that exceptions inside on_expire callbacks are caught and ignored."""
    tid = TempID.new("10m")
    tid.expires_at = 0  # Force it to be expired

    def bad_callback():
        raise RuntimeError("I crashed!")

    tid.on_expire(bad_callback)

    # Trigger callbacks via valid()
    assert tid.valid() is False
