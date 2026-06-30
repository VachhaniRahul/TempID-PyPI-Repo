# sync_backends

These examples show how to configure a synchronous database backend to enable strict `max_uses` limits.

Call `configure(store=...)` once at app startup. Call `teardown()` at shutdown.

| File | Backend | Use case |
|------|---------|----------|
| `sqlite_example.py` | SQLite | Single-server apps |
| `redis_example.py` | Redis | Distributed / multi-server |
| `postgres_example.py` | PostgreSQL | High-concurrency production |
| `mysql_example.py` | MySQL | MySQL / MariaDB |
| `mongo_example.py` | MongoDB | Document-based apps |

**Install the required driver first:**
```bash
pip install tempid[redis]      # for redis_example.py
pip install tempid[postgres]   # for postgres_example.py
pip install tempid[mysql]      # for mysql_example.py
pip install tempid[mongo]      # for mongo_example.py
# SQLite needs no extra install
```
