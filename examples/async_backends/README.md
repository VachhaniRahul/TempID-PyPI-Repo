# async_backends

These examples show how to use TempID with `async/await` in an asyncio environment (FastAPI, Starlette, etc.).

Use `verify_async()`, `use_async()`, and `teardown_async()` instead of their sync counterparts.

| File | Backend | Use case |
|------|---------|----------|
| `async_redis_example.py` | Redis (asyncio) | Async scripts and frameworks |

**Install:**
```bash
pip install "tempid[redis]"
python async_redis_example.py
```
