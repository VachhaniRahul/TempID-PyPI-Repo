"""
tempid.async_backends — Pluggable async use-count backends for max_uses tokens.

Usage::

    from tempid import configure
    from tempid.async_backends import AsyncRedisBackend

    configure(store=AsyncRedisBackend("redis://localhost:6379"))
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

from .backends import _LUA_INCR


class AsyncMemoryBackend:
    """
    In-process memory backend (Async). Zero dependencies.
    Suitable for single-worker ASGI deployments (FastAPI dev server).
    WARNING: Not for multi-worker production.
    """

    def __init__(self) -> None:
        self._lock: asyncio.Lock | None = None
        self._store: dict[str, int] = {}
        self._expiry: dict[str, int] = {}

    def _get_lock(self) -> asyncio.Lock:
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock

    async def increment_use(self, token_id: str, max_uses: int, expires_at: int = 0) -> bool:
        async with self._get_lock():
            self._gc()
            current = self._store.get(token_id, 0)
            if current >= max_uses:
                return False
            self._store[token_id] = current + 1
            if expires_at:
                self._expiry[token_id] = expires_at
            return True

    async def use_count(self, token_id: str) -> int:
        async with self._get_lock():
            return self._store.get(token_id, 0)

    def _gc(self) -> None:
        """Lazy garbage collection — remove expired token entries."""
        now = int(time.time())
        expired = [tid for tid, exp in self._expiry.items() if exp < now]
        for tid in expired:
            self._store.pop(tid, None)
            self._expiry.pop(tid, None)

    async def aclose(self) -> None:
        """No-op for AsyncMemoryBackend."""
        pass


class AsyncSQLiteBackend:
    """
    SQLite backend (Async). Persists use counts across server restarts.
    Requires: ``pip install tempid[async-sqlite]`` (installs aiosqlite).
    """

    def __init__(self, path: str = "tempid_uses.db") -> None:
        try:
            import aiosqlite  # type: ignore # noqa: F401
        except ImportError:
            raise ImportError(
                "AsyncSQLiteBackend requires aiosqlite. "
                "Install with: pip install tempid[async-sqlite]"
            )
        self._path = path
        self._lock: asyncio.Lock | None = None
        self._pool_created = False
        self._conn: Any = None

    def _get_lock(self) -> asyncio.Lock:
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock

    async def _setup(self) -> None:
        if self._pool_created:
            return
            
        import aiosqlite
        try:
            self._conn = await aiosqlite.connect(self._path, timeout=10)
            await self._conn.execute("PRAGMA journal_mode=WAL")
            await self._conn.execute("""
                CREATE TABLE IF NOT EXISTS tempid_uses (
                    token_id   TEXT PRIMARY KEY,
                    count      INTEGER NOT NULL DEFAULT 0,
                    expires_at INTEGER NOT NULL DEFAULT 0
                )
            """)
            await self._conn.commit()
            self._pool_created = True
        except Exception:
            if self._conn:
                await self._conn.close()
                self._conn = None
            raise

    async def increment_use(self, token_id: str, max_uses: int, expires_at: int = 0) -> bool:
        async with self._get_lock():
            await self._setup()
            await self._cleanup()
            
            async with self._conn.execute(
                "SELECT count FROM tempid_uses WHERE token_id = ?", (token_id,)
            ) as cursor:
                row = await cursor.fetchone()
                
            current = row[0] if row else 0
            if current >= max_uses:
                return False
                
            await self._conn.execute(
                "INSERT INTO tempid_uses (token_id, count, expires_at) VALUES (?, 1, ?) "
                "ON CONFLICT(token_id) DO UPDATE SET count = count + 1",
                (token_id, expires_at),
            )
            await self._conn.commit()
            return True

    async def use_count(self, token_id: str) -> int:
        async with self._get_lock():
            await self._setup()
            async with self._conn.execute(
                "SELECT count FROM tempid_uses WHERE token_id = ?", (token_id,)
            ) as cursor:
                row = await cursor.fetchone()
            return row[0] if row else 0

    async def aclose(self) -> None:
        if self._conn:
            await self._conn.close()
            self._conn = None

    async def _cleanup(self) -> None:
        await self._conn.execute(
            "DELETE FROM tempid_uses WHERE expires_at > 0 AND expires_at < ?",
            (int(time.time()),),
        )
        await self._conn.commit()


class AsyncRedisBackend:
    """
    Redis backend (Async). Safe for distributed, multi-worker deployments.
    Requires: ``pip install tempid[async-redis]``
    """

    def __init__(self, uri: str = "redis://localhost:6379/0", prefix: str = "tempid:") -> None:
        try:
            import redis.asyncio as redis  # type: ignore
        except ImportError:
            raise ImportError(
                "AsyncRedisBackend requires redis-py. "
                "Install with: pip install tempid[async-redis]"
            )
        self._pool = redis.from_url(uri, decode_responses=True)
        self.prefix = prefix
        # Pre-register the script hash for performance
        self._incr_script = self._pool.register_script(_LUA_INCR)

    async def increment_use(self, token_id: str, max_uses: int, expires_at: int = 0) -> bool:
        key = f"{self.prefix}{token_id}"
        # Lua script handles both INCR and TTL atomically to avoid race conditions
        count = await self._incr_script(keys=[key], args=[max_uses, expires_at])
        
        # Redis Lua script returns 0 if limit exceeded
        if count == 0:
            return False
            
        return True

    async def use_count(self, token_id: str) -> int:
        key = f"{self.prefix}{token_id}"
        val = await self._pool.get(key)
        return int(val) if val else 0

    async def aclose(self) -> None:
        if self._pool:
            await self._pool.aclose()


class AsyncMongoBackend:
    """
    MongoDB backend (Async). Safe for distributed, multi-worker deployments.
    Uses ``find_one_and_update`` for atomic document-level operations.
    Requires: ``pip install tempid[async-mongo]``
    """

    def __init__(self, uri: str = "mongodb://localhost:27017", db: str = "tempid") -> None:
        try:
            from motor.motor_asyncio import AsyncIOMotorClient
        except ImportError:
            raise ImportError(
                "AsyncMongoBackend requires motor. "
                "Install with: pip install tempid[async-mongo]"
            )
        self._client: Any = AsyncIOMotorClient(uri)
        self._col: Any = self._client[db]["uses"]
        self._setup_lock = asyncio.Lock()
        self._setup_done = False

    async def _setup(self) -> None:
        if self._setup_done:
            return
        async with self._setup_lock:
            if self._setup_done:
                return
            await self._col.create_index("token_id", unique=True)
            await self._col.create_index("expires_at", expireAfterSeconds=0, sparse=True)
            self._setup_done = True

    async def increment_use(self, token_id: str, max_uses: int, expires_at: int = 0) -> bool:
        from pymongo.errors import DuplicateKeyError
        await self._setup()
        try:
            await self._col.insert_one({"token_id": token_id, "count": 1, "expires_at": expires_at})
            return True
        except DuplicateKeyError:
            result = await self._col.find_one_and_update(
                {"token_id": token_id, "count": {"$lt": max_uses}},
                {"$inc": {"count": 1}},
                return_document=True,
            )
            return result is not None

    async def use_count(self, token_id: str) -> int:
        await self._setup()
        doc = await self._col.find_one({"token_id": token_id})
        return doc["count"] if doc else 0

    async def aclose(self) -> None:
        """Motor closes the client automatically on event loop teardown, but can be closed explicitly."""
        if self._client:
            self._client.close()


class AsyncPostgreSQLBackend:
    """
    PostgreSQL backend (Async). Uses asyncpg.
    Requires: ``pip install tempid[async-postgres]``
    """

    def __init__(
        self,
        dsn: str = "postgresql://localhost/tempid",
        min_conn: int = 2,
        max_conn: int = 10,
    ) -> None:
        try:
            import asyncpg  # type: ignore # noqa: F401
        except ImportError:
            raise ImportError(
                "AsyncPostgreSQLBackend requires asyncpg. "
                "Install with: pip install tempid[async-postgres]"
            )
        self.dsn = dsn
        self.min_conn = min_conn
        self.max_conn = max_conn
        self._pool = None
        self._setup_lock = asyncio.Lock()

    async def _get_pool(self):
        import asyncpg
        if self._pool is None:
            async with self._setup_lock:
                if self._pool is None:
                    # 1. Create pool in local variable
                    pool = await asyncpg.create_pool(
                        self.dsn, min_size=self.min_conn, max_size=self.max_conn
                    )
                    # 2. Setup tables using the local pool
                    async with pool.acquire() as conn:
                        await conn.execute("""
                            CREATE TABLE IF NOT EXISTS tempid_uses (
                                token_id   TEXT PRIMARY KEY,
                                count      INTEGER NOT NULL DEFAULT 0,
                                expires_at INTEGER NOT NULL DEFAULT 0
                            )
                        """)
                    # 3. Assign self._pool LAST to prevent race condition leaks
                    self._pool = pool
        return self._pool

    async def increment_use(self, token_id: str, max_uses: int, expires_at: int = 0) -> bool:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            async with conn.transaction():
                row = await conn.fetchrow(
                    """
                    INSERT INTO tempid_uses (token_id, count, expires_at)
                    VALUES ($1, 1, $2)
                    ON CONFLICT (token_id) DO UPDATE
                    SET count = tempid_uses.count + 1
                    WHERE tempid_uses.count < $3
                    RETURNING count
                    """,
                    token_id, expires_at, max_uses
                )
        return row is not None

    async def use_count(self, token_id: str) -> int:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow("SELECT count FROM tempid_uses WHERE token_id = $1", token_id)
        return row["count"] if row else 0

    async def aclose(self) -> None:
        if self._pool:
            await self._pool.close()


class AsyncMySQLBackend:
    """
    MySQL backend (Async). Uses aiomysql.
    Requires: ``pip install tempid[async-mysql]``
    """

    def __init__(
        self,
        host: str = "localhost",
        port: int = 3306,
        user: str = "root",
        password: str = "",
        db: str = "tempid",
        max_connections: int = 10,
    ) -> None:
        try:
            import aiomysql  # type: ignore # noqa: F401
        except ImportError:
            raise ImportError(
                "AsyncMySQLBackend requires aiomysql. "
                "Install with: pip install tempid[async-mysql]"
            )
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.db = db
        self.max_connections = max_connections
        self._pool = None
        self._setup_lock = asyncio.Lock()

    async def _get_pool(self):
        import aiomysql
        if self._pool is None:
            async with self._setup_lock:
                if self._pool is None:
                    # 1. Create pool in local variable with explicit autocommit=False
                    pool = await aiomysql.create_pool(
                        host=self.host,
                        port=self.port,
                        user=self.user,
                        password=self.password,
                        db=self.db,
                        minsize=1,
                        maxsize=self.max_connections,
                        autocommit=False,
                    )
                    # 2. Setup tables using the local pool
                    async with pool.acquire() as conn:
                        async with conn.cursor() as cur:
                            await cur.execute("""
                                CREATE TABLE IF NOT EXISTS tempid_uses (
                                    token_id   VARCHAR(64) PRIMARY KEY,
                                    count      INT         NOT NULL DEFAULT 0,
                                    expires_at INT         NOT NULL DEFAULT 0
                                )
                            """)
                        await conn.commit()
                    # 3. Assign self._pool LAST to prevent race condition leaks
                    self._pool = pool
        return self._pool

    async def increment_use(self, token_id: str, max_uses: int, expires_at: int = 0) -> bool:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            try:
                async with conn.cursor() as cur:
                    await cur.execute(
                        "SELECT count FROM tempid_uses WHERE token_id = %s FOR UPDATE",
                        (token_id,)
                    )
                    row = await cur.fetchone()
                    
                    if row and row[0] >= max_uses:
                        await conn.rollback()
                        return False
                        
                    await cur.execute(
                        "INSERT INTO tempid_uses (token_id, count, expires_at) VALUES (%s, 1, %s) "
                        "ON DUPLICATE KEY UPDATE count = count + 1",
                        (token_id, expires_at),
                    )
                await conn.commit()
                return True
            except Exception:
                await conn.rollback()
                raise

    async def use_count(self, token_id: str) -> int:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    "SELECT count FROM tempid_uses WHERE token_id = %s", (token_id,)
                )
                row = await cur.fetchone()
        return row[0] if row else 0

    async def aclose(self) -> None:
        if self._pool:
            self._pool.close()
            await self._pool.wait_closed()
