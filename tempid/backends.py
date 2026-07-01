"""
tempid.backends — Pluggable use-count backends for max_uses tokens.

Default backend is MemoryBackend (zero dependencies, single-process only).
For production multi-worker deployments, use RedisBackend, MongoBackend,
MySQLBackend, or PostgreSQLBackend.

Usage::

    from tempid import TempID
    from tempid.backends import RedisBackend

    TempID.configure(store=RedisBackend("redis://localhost:6379"))
"""

from __future__ import annotations

import threading
import time
from typing import Protocol, runtime_checkable


@runtime_checkable
class BaseBackend(Protocol):
    """Protocol that all backends must satisfy."""

    def increment_use(self, token_id: str, max_uses: int, expires_at: int = 0) -> bool:
        """Atomically increment use count. Returns True if allowed, False if limit reached."""
        ...

    def use_count(self, token_id: str) -> int:
        """Return current use count for a token_id."""
        ...

    def close(self) -> None:
        """Close backend connections and release resources."""
        ...


@runtime_checkable
class AsyncBaseBackend(Protocol):
    """Protocol that all async backends must satisfy."""

    async def increment_use(self, token_id: str, max_uses: int, expires_at: int = 0) -> bool:
        """Atomically increment use count asynchronously. Returns True if allowed, False if limit reached."""
        ...

    async def use_count(self, token_id: str) -> int:
        """Return current use count for a token_id asynchronously."""
        ...

    async def aclose(self) -> None:
        """Close backend connections and release resources asynchronously."""
        ...


class MemoryBackend:
    """
    In-process memory backend. Zero dependencies.

    Suitable for: development, single-process apps (Flask dev server,
    FastAPI with 1 worker, scripts).

    WARNING: NOT suitable for multi-worker production deployments.
    Under Gunicorn/Uvicorn with multiple workers, each process has its
    own memory — each worker tracks uses independently. A token with
    max_uses=1 could be used N times across N workers.
    Use RedisBackend for distributed deployments.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._store: dict[str, int] = {}
        self._expiry: dict[str, int] = {}

    def increment_use(self, token_id: str, max_uses: int, expires_at: int = 0) -> bool:
        with self._lock:
            self._gc()
            current = self._store.get(token_id, 0)
            if current >= max_uses:
                return False
            self._store[token_id] = current + 1
            if expires_at:
                self._expiry[token_id] = expires_at
            return True

    def use_count(self, token_id: str) -> int:
        with self._lock:
            return self._store.get(token_id, 0)

    def close(self) -> None:
        """No-op for MemoryBackend."""
        pass

    def _gc(self) -> None:
        """Lazy garbage collection — remove expired token entries."""
        now = int(time.time())
        expired = [tid for tid, exp in self._expiry.items() if exp < now]
        for tid in expired:
            self._store.pop(tid, None)
            self._expiry.pop(tid, None)


class SQLiteBackend:
    """
    SQLite backend. Persists use counts across server restarts.
    Safe for single-machine, multi-threaded deployments (WAL mode).

    Args:
        path: Path to the SQLite database file. Defaults to ``"tempid_uses.db"``.

    WARNING: NOT suitable for distributed multi-machine deployments.
    Use RedisBackend for that.
    """

    def __init__(self, path: str = "tempid_uses.db") -> None:
        import sqlite3
        from typing import Any

        self._lock = threading.Lock()
        self._conn: Any = sqlite3.connect(path, check_same_thread=False, timeout=10)
        self._conn.execute("PRAGMA journal_mode=WAL")  # concurrent reads/writes
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS tempid_uses (
                token_id   TEXT PRIMARY KEY,
                count      INTEGER NOT NULL DEFAULT 0,
                expires_at INTEGER NOT NULL DEFAULT 0
            )
        """)
        self._conn.commit()

    def increment_use(self, token_id: str, max_uses: int, expires_at: int = 0) -> bool:
        with self._lock:
            self._cleanup()
            cur = self._conn.execute(
                "SELECT count FROM tempid_uses WHERE token_id = ?", (token_id,)
            ).fetchone()
            current = cur[0] if cur else 0
            if current >= max_uses:
                return False
            self._conn.execute(
                "INSERT INTO tempid_uses (token_id, count, expires_at) VALUES (?, 1, ?) "
                "ON CONFLICT(token_id) DO UPDATE SET count = count + 1",
                (token_id, expires_at),
            )
            self._conn.commit()
            return True

    def use_count(self, token_id: str) -> int:
        with self._lock:
            cur = self._conn.execute(
                "SELECT count FROM tempid_uses WHERE token_id = ?", (token_id,)
            ).fetchone()
            return cur[0] if cur else 0

    def _cleanup(self) -> None:
        """Delete rows for expired tokens — prevents unbounded DB growth."""
        self._conn.execute(
            "DELETE FROM tempid_uses WHERE expires_at > 0 AND expires_at < ?",
            (int(time.time()),),
        )
        self._conn.commit()

    def close(self) -> None:
        with self._lock:
            if self._conn:
                self._conn.close()
                self._conn = None


# Atomic Lua script — executes as a single Redis command, no race conditions possible
_LUA_INCR = """
local current = redis.call('INCR', KEYS[1])
if current > tonumber(ARGV[1]) then
    redis.call('DECR', KEYS[1])
    return 0
end
local expires_at = tonumber(ARGV[2])
if current == 1 and expires_at and expires_at > 0 then
    -- Convert unix timestamp (seconds) to milliseconds for PEXPIREAT
    redis.call('PEXPIREAT', KEYS[1], expires_at * 1000)
end
return 1
"""


class RedisBackend:
    """
    Redis backend. Safe for distributed, multi-worker production deployments.
    Uses an atomic Lua script to guarantee no race conditions under concurrency.

    Args:
        url: Redis connection URL. Defaults to ``"redis://localhost:6379"``.

    Requires: ``pip install tempid[redis]``
    """

    def __init__(self, url: str = "redis://localhost:6379") -> None:
        try:
            import redis as redis_lib
        except ImportError:
            raise ImportError(
                "RedisBackend requires the redis package. "
                "Install it with: pip install tempid[redis]"
            )
        self._redis = redis_lib.from_url(url)

    def increment_use(self, token_id: str, max_uses: int, expires_at: int = 0) -> bool:
        # Lua executes atomically in Redis — impossible to race
        result = self._redis.eval(_LUA_INCR, 1, f"tempid:{token_id}", max_uses, expires_at)
        return bool(result)

    def use_count(self, token_id: str) -> int:
        val = self._redis.get(f"tempid:{token_id}")
        return int(val) if val else 0

    def close(self) -> None:
        self._redis.close()


class MongoBackend:
    """
    MongoDB backend. Safe for distributed, multi-worker production deployments.
    Uses ``find_one_and_update`` for atomic document-level operations.

    Args:
        uri: MongoDB connection URI. Defaults to ``"mongodb://localhost:27017"``.
        db:  Database name. Defaults to ``"tempid"``.

    Requires: ``pip install tempid[mongo]``
    """

    def __init__(self, uri: str = "mongodb://localhost:27017", db: str = "tempid") -> None:
        try:
            from pymongo import MongoClient
        except ImportError:
            raise ImportError(
                "MongoBackend requires the pymongo package. "
                "Install it with: pip install tempid[mongo]"
            )
        from typing import Any

        self._col: Any = MongoClient(uri)[db]["uses"]
        self._col.create_index("token_id", unique=True)

    def increment_use(self, token_id: str, max_uses: int, expires_at: int = 0) -> bool:
        from pymongo.errors import DuplicateKeyError

        try:
            # We assume max_uses >= 1 here. This is safely enforced by TempID.use()
            # which skips the backend entirely if max_uses == 0.
            self._col.insert_one({"token_id": token_id, "count": 1, "expires_at": expires_at})
            return True
        except DuplicateKeyError:
            result = self._col.find_one_and_update(
                {"token_id": token_id, "count": {"$lt": max_uses}},
                {"$inc": {"count": 1}},
                return_document=True,
            )
            return result is not None

    def use_count(self, token_id: str) -> int:
        doc = self._col.find_one({"token_id": token_id})
        return doc["count"] if doc else 0

    def close(self) -> None:
        if hasattr(self, "_col") and self._col.database.client:
            self._col.database.client.close()


class MySQLBackend:
    """
    MySQL/MariaDB backend. Safe for single and multi-machine deployments.
    Uses a connection pool and ``SELECT FOR UPDATE`` within an explicit
    transaction for atomic increments.

    Args:
        host, port, user, password, db: MySQL connection parameters.
        max_connections: Pool size. Defaults to ``10``.

    Requires: ``pip install tempid[mysql]``
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
            import pymysql
            from dbutils.pooled_db import PooledDB
        except ImportError:
            raise ImportError(
                "MySQLBackend requires pymysql and dbutils. Install with: pip install tempid[mysql]"
            )
        self._pool = PooledDB(
            creator=pymysql,
            maxconnections=max_connections,
            host=host,
            port=port,
            user=user,
            password=password,
            database=db,
        )
        self._setup()

    def _setup(self) -> None:
        conn = self._pool.connection()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS tempid_uses (
                        token_id   VARCHAR(64) PRIMARY KEY,
                        count      INT         NOT NULL DEFAULT 0,
                        expires_at INT         NOT NULL DEFAULT 0
                    )
                """)
            conn.commit()
        finally:
            conn.close()

    def increment_use(self, token_id: str, max_uses: int, expires_at: int = 0) -> bool:
        conn = self._pool.connection()
        try:
            conn.begin()  # explicit transaction — required for FOR UPDATE to lock the row
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT count FROM tempid_uses WHERE token_id = %s FOR UPDATE",
                    (token_id,),
                )
                row = cur.fetchone()
                if row and row[0] >= max_uses:
                    conn.rollback()
                    return False
                cur.execute(
                    "INSERT INTO tempid_uses (token_id, count, expires_at) VALUES (%s, 1, %s) "
                    "ON DUPLICATE KEY UPDATE count = count + 1",
                    (token_id, expires_at),
                )
            conn.commit()
            return True
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def use_count(self, token_id: str) -> int:
        conn = self._pool.connection()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT count FROM tempid_uses WHERE token_id = %s", (token_id,))
                row = cur.fetchone()
                return row[0] if row else 0
        finally:
            conn.close()

    def close(self) -> None:
        self._pool.close()


class PostgreSQLBackend:
    """
    PostgreSQL backend. Safe for distributed, multi-worker production deployments.
    Uses a connection pool and ``SELECT FOR UPDATE`` within a transaction
    for atomic increments.

    Args:
        dsn: PostgreSQL connection DSN. Defaults to ``"postgresql://localhost/tempid"``.
        min_conn: Minimum pool connections. Defaults to ``2``.
        max_conn: Maximum pool connections. Defaults to ``10``.

    Requires: ``pip install tempid[postgres]``
    """

    def __init__(
        self,
        dsn: str = "postgresql://localhost/tempid",
        min_conn: int = 2,
        max_conn: int = 10,
    ) -> None:
        try:
            from psycopg2 import pool as pg_pool
        except ImportError:
            raise ImportError(
                "PostgreSQLBackend requires psycopg2. Install with: pip install tempid[postgres]"
            )
        self._pool = pg_pool.ThreadedConnectionPool(min_conn, max_conn, dsn=dsn)
        self._setup()

    def _setup(self) -> None:
        conn = self._pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS tempid_uses (
                        token_id   TEXT PRIMARY KEY,
                        count      INTEGER NOT NULL DEFAULT 0,
                        expires_at INTEGER NOT NULL DEFAULT 0
                    )
                """)
            conn.commit()
        finally:
            self._pool.putconn(conn)

    def increment_use(self, token_id: str, max_uses: int, expires_at: int = 0) -> bool:
        conn = self._pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO tempid_uses (token_id, count, expires_at)
                    VALUES (%s, 1, %s)
                    ON CONFLICT (token_id) DO UPDATE
                    SET count = tempid_uses.count + 1
                    WHERE tempid_uses.count < %s
                    RETURNING count
                    """,
                    (token_id, expires_at, max_uses),
                )
                row = cur.fetchone()
            conn.commit()
            return row is not None
        except Exception:
            conn.rollback()
            raise
        finally:
            self._pool.putconn(conn)

    def use_count(self, token_id: str) -> int:
        conn = self._pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT count FROM tempid_uses WHERE token_id = %s", (token_id,))
                row = cur.fetchone()
                return row[0] if row else 0
        finally:
            self._pool.putconn(conn)

    def close(self) -> None:
        self._pool.closeall()
