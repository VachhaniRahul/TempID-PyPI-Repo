import os
import pytest
import asyncio

from tempid import TempID, configure
from tempid.async_backends import AsyncMemoryBackend, AsyncSQLiteBackend


def fresh_async_memory():
    backend = AsyncMemoryBackend()
    configure(store=backend)
    return backend


@pytest.fixture
def aio_sqlite_db():
    import tempfile

    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)

    backend = AsyncSQLiteBackend(path)
    configure(store=backend)

    yield backend

    os.remove(path)


@pytest.mark.asyncio
async def test_async_memory_unlimited():
    fresh_async_memory()
    tid = TempID.new("10m")

    assert tid.max_uses == 0
    # verify_async should work
    assert await TempID.verify_async(tid.value, check_uses=True) is not None

    for _ in range(5):
        assert await tid.use_async() is True


@pytest.mark.asyncio
async def test_async_memory_limited():
    fresh_async_memory()
    tid = TempID.new("10m", max_uses=2)

    assert await tid.use_async() is True
    assert await tid.use_async() is True
    assert await tid.use_async() is False  # 3rd is rejected

    info = await tid.uses_info_async()
    assert info["used"] == 2
    assert info["left"] == 0

    # check_uses=True should return None for exhausted
    assert await TempID.verify_async(tid.value, check_uses=True) is None


@pytest.mark.asyncio
async def test_async_sqlite(aio_sqlite_db):
    tid = TempID.new("10m", max_uses=1)

    # Test valid initial state
    assert await tid.uses_info_async() == {"total": 1, "used": 0, "left": 1}
    assert await TempID.verify_async(tid.value, check_uses=True) is not None

    # Use it
    assert await tid.use_async() is True
    assert await tid.use_async() is False

    assert await tid.uses_info_async() == {"total": 1, "used": 1, "left": 0}
    assert await TempID.verify_async(tid.value, check_uses=True) is None


@pytest.mark.asyncio
async def test_async_sync_mismatch_raises_errors():
    """Test that trying to use sync methods on an async backend throws."""
    fresh_async_memory()
    tid = TempID.new("10m", max_uses=1)

    with pytest.raises(RuntimeError, match="Configured backend is async"):
        tid.use()

    with pytest.raises(RuntimeError, match="Configured backend is async"):
        tid.uses_info()


@pytest.mark.asyncio
async def test_sync_async_mismatch_raises_errors():
    """Test that trying to use async methods on a sync backend throws."""
    from tempid.backends import MemoryBackend

    configure(store=MemoryBackend())
    tid = TempID.new("10m", max_uses=1)

    with pytest.raises(RuntimeError, match="Configured backend is sync"):
        await tid.use_async()

    with pytest.raises(RuntimeError, match="Configured backend is sync"):
        await tid.uses_info_async()


def test_unawaited_async_method_does_not_consume_uses():
    """Test that calling an async method without awaiting it just returns a coroutine and does nothing."""
    import inspect
    import warnings
    from tempid.backends import MemoryBackend

    configure(store=MemoryBackend())
    tid = TempID.new("10m", max_uses=2)

    # Call the async method without awaiting it (like the user did)
    # We catch the RuntimeWarning to keep the test output clean
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", RuntimeWarning)
        coro = tid.use_async()

    # Prove that it just returned a coroutine object, but didn't execute the function body
    assert inspect.iscoroutine(coro)

    # Prove that the use count was NOT consumed (still 2 left)
    assert tid.uses_info()["used"] == 0
    assert tid.uses_info()["left"] == 2

    # Close the coroutine to prevent pytest from throwing a RuntimeWarning during teardown
    coro.close()

    # Now use the normal sync method to prove it still works from scratch
    assert tid.use() is True
    assert tid.uses_info()["used"] == 1


@pytest.mark.asyncio
async def test_verify_async_invalid_returns_none():
    """Test that verify_async properly returns None for invalid tokens."""
    fresh_async_memory()

    # Completely invalid format
    assert await TempID.verify_async("not-a-token") is None

    # Valid format but expired
    tid = TempID.new("1s")
    await asyncio.sleep(1.1)
    assert await TempID.verify_async(tid.value) is None
