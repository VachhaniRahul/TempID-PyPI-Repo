# Changelog

All notable changes to this project will be documented in this file.

---

## [2.0.1] — 2026-06-30

### Documentation
- Reorganized `examples/` into `basics/`, `sync_backends/`, `async_backends/`, and `use_cases/`
- Added production-ready FastAPI middleware and forgot-password examples
- Added `all_methods_demo.py` for a quick tour of the API
- Rewrote `README.md` for zero-knowledge beginners (clearer backend explanations, teardown warnings)
- Added `CONTRIBUTING.md` to meet open-source standards

---

## [2.0.0] — 2026-06-30

### Added
- Full synchronous backends: `SQLiteBackend`, `RedisBackend`, `PostgreSQLBackend`, `MySQLBackend`, `MongoBackend`
- Full asynchronous backends: `AsyncSQLiteBackend`, `AsyncRedisBackend`, `AsyncPostgreSQLBackend`, `AsyncMySQLBackend`, `AsyncMongoBackend`
- Unified `teardown()` and `teardown_async()` for graceful connection pool shutdown
- `py.typed` marker for full type-checker support

### Changed
- Token format upgraded to `V2` — improved header structure with 5-byte timestamp and 4-byte nonce
- Payload encryption upgraded to `AES-GCM` via HKDF-derived key
- `max_uses` now stored in token header (1 byte) for stateless pre-check

### Fixed
- Race condition in `MemoryBackend` under high concurrency (added `threading.Lock`)
- Connection pool leak in async backends during stress tests


