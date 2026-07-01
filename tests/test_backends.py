import pytest
import tempfile

from tempid import TempID, configure, MemoryBackend, SQLiteBackend


def fresh_memory():
    backend = MemoryBackend()
    configure(store=backend)
    return backend


def test_unlimited_token_always_passes():
    fresh_memory()
    tid = TempID.new("10m")  # max_uses defaults to 0 = unlimited
    assert tid.max_uses == 0
    for _ in range(10):
        assert tid.use() is True


def test_single_use_token_memory():
    fresh_memory()
    tid = TempID.new("10m", max_uses=1)
    assert tid.use() is True  # 1st — allowed
    assert tid.use() is False


def test_n_use_token_memory():
    fresh_memory()
    tid = TempID.new("10m", max_uses=3)
    assert tid.use() is True
    assert tid.use() is True
    assert tid.use() is True
    assert tid.use() is False


def test_uses_info_memory():
    fresh_memory()
    tid = TempID.new("10m", max_uses=3)
    tid.use()
    tid.use()
    info = tid.uses_info()
    assert info["total"] == 3
    assert info["used"] == 2
    assert info["left"] == 1


def test_uses_info_unlimited():
    fresh_memory()
    tid = TempID.new("10m")
    info = tid.uses_info()
    assert info == {"total": None, "used": None, "left": None}


def test_max_uses_survives_roundtrip():
    """max_uses must be preserved after from_string()."""
    fresh_memory()
    tid = TempID.new("10m", max_uses=5)
    restored = TempID.from_string(tid.value)
    assert restored.max_uses == 5


def test_max_uses_validation():
    fresh_memory()
    with pytest.raises(ValueError):
        TempID.new("10m", max_uses=256)  # out of range
    with pytest.raises(ValueError):
        TempID.new("10m", max_uses=-1)


def test_verify_check_uses_exhausted():
    """Verify should return None if check_uses=True and token is exhausted."""
    fresh_memory()
    tid = TempID.new("10m", max_uses=1)
    tid.use()  # consume it

    # Standard verify still works (math is valid)
    assert TempID.verify(tid.value) is not None

    # check_uses=True fails because uses are 0
    assert TempID.verify(tid.value, check_uses=True) is None


def test_verify_check_uses_does_not_consume():
    """Verify with check_uses=True should NOT consume the token."""
    fresh_memory()
    tid = TempID.new("10m", max_uses=1)

    # Checking it doesn't consume it
    assert TempID.verify(tid.value, check_uses=True) is not None
    assert TempID.verify(tid.value, check_uses=True) is not None

    # It can still be used
    assert tid.use() is True


def test_single_use_token_sqlite():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    configure(store=SQLiteBackend(db_path))

    tid = TempID.new("10m", max_uses=1)
    assert tid.use() is True
    assert tid.use() is False


def test_n_use_token_sqlite():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    configure(store=SQLiteBackend(db_path))

    tid = TempID.new("10m", max_uses=3)
    assert tid.use() is True
    assert tid.use() is True
    assert tid.use() is True
    assert tid.use() is False


def test_uses_info_sqlite():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    configure(store=SQLiteBackend(db_path))

    tid = TempID.new("10m", max_uses=5)
    tid.use()
    tid.use()
    tid.use()
    info = tid.uses_info()
    assert info["total"] == 5
    assert info["used"] == 3
    assert info["left"] == 2
