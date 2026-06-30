# tempid

> Unique IDs that automatically expire, store encrypted payloads, and strictly limit usages — built for Enterprise Python.

`tempid` gives you Stripe-like, highly secure temporary tokens (`TEMP-V2.XXXX...`) without the boilerplate. 

`tempid` operates as a full **Hybrid Token Engine**. It supports embedded JSON payloads, Strict Use-Count Limits (e.g. "burn after reading"), and high-concurrency Async/Sync database backends.

---

## ⚡ Features at a Glance
- **Stateless by Default:** Tokens hold their own expiration time. No database required for basic time-based expiry.
- **Encrypted Payloads:** Embed JSON data directly inside the token (up to 512 bytes). Fully encrypted, users cannot read or tamper with it.
- **Strict Use Limits:** Set a `max_uses` limit on tokens (e.g., a one-time-use OTP).
- **Enterprise DB Backends:** Built-in connection pooling for Redis, PostgreSQL, MySQL, SQLite, and MongoDB.
- **Hybrid Async Engine:** First-class `async/await` support for FastAPI, Sanic, and Starlette via dedicated `AsyncBackends`.
- **Zero Dependencies (Core):** The core engine uses only standard Python libraries.

---

## 📦 Installation

```bash
pip install tempid
```

If you plan to use database backends for strict usage limits (`max_uses`), install the appropriate driver:
```bash
pip install tempid[redis]          # For RedisBackend
pip install tempid[mysql]          # For MySQLBackend
pip install tempid[postgres]       # For PostgreSQLBackend
pip install tempid[mongo]          # For MongoBackend
pip install tempid[async-postgres] # For AsyncPostgreSQLBackend
pip install tempid[async-mysql]    # For AsyncMySQLBackend
pip install tempid[async-mongo]    # For AsyncMongoBackend
pip install tempid[all]            # Install all drivers
```

---

## 🚀 Quick Start (Stateless Mode)

By default, `tempid` operates completely offline without needing a database. Expiration is cryptographically signed into the token itself.

```python
from tempid import TempID

# 1. Create a token that expires in 15 minutes
tid = TempID.new("15m")
print(tid.value)  # TEMP-V2.AIAGU-PSOHJ...

# 2. Check time remaining
print(tid.remaining())  # "14m 59s"

# 3. Verify securely (e.g., when a user submits it)
# verify() returns the TempID object if valid, or None if expired/tampered
verified = TempID.verify(tid.value)
if verified:
    print("Token is valid!")
else:
    print("Token is invalid or expired.")
```

---

## 🧳 Encrypted Payloads

You can embed JSON-serializable dictionaries directly into the token. The data is heavily compressed (zlib) and **fully encrypted** (AES-like CTR mode). Users cannot read or tamper with it.

```python
# Create a token with a payload
tid = TempID.new("2h", payload={"user_id": 42, "role": "admin"})

# Later, verify and extract the data
verified_token = TempID.verify(tid.value)

if verified_token:
    print(verified_token.payload["user_id"])  # 42
    print(verified_token.payload["role"])     # "admin"
```
*Note: Maximum payload size after compression is 512 bytes. If exceeded, `TempIDPayloadTooLargeError` is raised.*

---

## 🛡️ Strict Use Limits (`max_uses`)

Need a token that can only be used exactly 3 times, or a password reset link that burns after 1 use? You can set `max_uses`.

To use this feature, you **must** configure a database backend at application startup so `tempid` can track the usage atomically across your servers.

### 1. Configure a Backend (Startup)
```python
from tempid import configure
from tempid.backends import RedisBackend

# Run this ONCE when your app starts
configure(store=RedisBackend("redis://localhost:6379/0"))
```

### 2. Generate a Limited Token
```python
# Expires in 1 hour, OR after 1 successful use
tid = TempID.new("1h", max_uses=1)
```

### 3. Consume the Token
```python
# check_uses=True checks the database limit WITHOUT consuming a use
verified = TempID.verify(token_str, check_uses=True)

if verified:
    # use() attempts to consume 1 use atomically in the database
    if verified.use():
        print("Success! Action performed.")
    else:
        print("Token limit reached (Already used!).")
```

### 4. Check Remaining Uses
```python
info = verified.uses_info()
print(f"Used: {info['used']} / Total: {info['total']}")
```

---

## ⚡ Async Support (FastAPI / Starlette)

`tempid` is fully async-native. If you are building high-concurrency apps, use the `Async` backends and methods to prevent blocking your event loop.

```python
import asyncio
from tempid import TempID, configure
from tempid.async_backends import AsyncPostgreSQLBackend

# 1. Configure the Async Backend
configure(store=AsyncPostgreSQLBackend("postgresql://root:pass@localhost/mydb"))

async def api_endpoint(token_string: str):
    # 2. Verify (Checks DB asynchronously without blocking)
    tid = await TempID.verify_async(token_string, check_uses=True)
    
    if not tid:
        return {"error": "Invalid or exhausted token"}
        
    # 3. Consume a use
    success = await tid.use_async()
    if success:
        return {"data": tid.payload}
    else:
        return {"error": "Token already used!"}
        
    # Check info
    info = await tid.uses_info_async()
    print(info)
```

---

## 🏭 Supported Backends Reference

All backends guarantee **perfect atomicity** (no race conditions or double-spending) even under extreme loads.

### Synchronous Backends (`tempid.backends`)
- `MemoryBackend()`: Stores uses in a thread-safe dict. (Development only).
- `SQLiteBackend(db_path)`: Uses WAL mode and locks. Great for single-server production.
- `RedisBackend(uri)`: Uses atomic Lua scripts. Ideal for distributed caching.
- `MongoBackend(uri, db)`: Uses `find_one_and_update` on unique indexes.
- `MySQLBackend(host, port, user, password, db)`: Connection pooled, uses `SELECT FOR UPDATE`.
- `PostgreSQLBackend(dsn)`: Connection pooled, uses `ON CONFLICT DO UPDATE`.

### Asynchronous Backends (`tempid.async_backends`)
- `AsyncMemoryBackend()`: Thread-safe, asyncio-safe. (Development only).
- `AsyncSQLiteBackend(db_path)`: Uses `aiosqlite`.
- `AsyncRedisBackend(uri)`: Uses `redis.asyncio` with Lua scripts.
- `AsyncMongoBackend(uri, db)`: Uses `motor`.
- `AsyncMySQLBackend(host, port, user, password, db)`: Uses `aiomysql` pools.
- `AsyncPostgreSQLBackend(dsn)`: Uses `asyncpg` pools (highest performance).

---

## 🔐 Security & Secrets

### The Secret Key (Required)
`tempid` uses a 96-bit HMAC-SHA256 signature to prevent tampering and encryption. In production, you **must** set an environment variable to share the secret across your instances.

```bash
# Set this in your OS, Docker, or .env
export TEMPID_SECRET="your-super-secret-32-byte-key-here"
```

To generate a highly secure secret, run:
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

### Encryption Engine
Payloads and timestamps are encrypted using a custom XOR-CTR stream cipher combined with HMAC-SHA256, ensuring no parts of the internal data can be deciphered without the `TEMPID_SECRET`.

---

## 📖 Complete API Reference

### `TempID` Core Class

#### `TempID.new(expires_in: str, payload: dict = None, max_uses: int = 0) -> TempID`
Creates a new token.
- `expires_in`: Duration string (e.g. `"30s"`, `"15m"`, `"2h"`, `"7d"`).
- `payload`: Optional dict. Must be JSON serializable. Max 512 bytes.
- `max_uses`: Strict use limit. `0` means unlimited.

#### `TempID.from_string(value: str) -> TempID`
Parses a token string but **does not verify** uses limit or signature. Used internally or for manual exception handling.

#### `TempID.verify(value: str, check_uses: bool = False) -> TempID | None`
The primary, safe way to verify a token. Returns the `TempID` object if valid, unexpired, and untampered. If `check_uses=True`, it verifies the backend limit without consuming a use. Returns `None` on any failure.

#### `await TempID.verify_async(value: str, check_uses: bool = False) -> TempID | None`
The async counterpart for `verify()`.

#### `tid.use() -> bool`
Attempts to consume 1 use in the database. Returns `True` if successful, `False` if the limit is reached or the token is expired.

#### `await tid.use_async() -> bool`
The async counterpart for `use()`.

#### `tid.uses_info() -> dict`
Returns `{"total": max_uses, "used": count, "left": remaining}`.

#### `await tid.uses_info_async() -> dict`
The async counterpart for `uses_info()`.

#### `tid.valid() -> bool`
Returns `True` if the token's timestamp has not expired. (Does NOT check database limits).

#### `tid.expired() -> bool`
Opposite of `valid()`.

#### `tid.remaining() -> str`
Returns a human-readable string of time left (e.g., `"1h 4m 3s"`, `"expired"`).

#### `tid.on_expire(callback: Callable) -> TempID`
Registers a function to be called exactly once when the token is first determined to be expired by `valid()`.

---

## ⚠️ Exceptions Reference

Located in `tempid.exceptions`.

| Exception | Reason Thrown |
|-----------|---------------|
| `TempIDFormatError` | The token string is malformed or invalid base32. |
| `TempIDTamperedError` | The HMAC signature does not match (someone tried to forge or alter it). |
| `TempIDExpiredError` | The token's timestamp has passed. |
| `TempIDPayloadTooLargeError`| Passed payload exceeds 512 compressed bytes. |
| `TempIDRevokedError` | (Reserved for future manual revocation feature). |

**Example of manual handling:**
```python
from tempid import TempID
from tempid.exceptions import TempIDFormatError, TempIDTamperedError

try:
    tid = TempID.from_string(user_input)
    if tid.valid():
        print(tid.payload)
except TempIDTamperedError:
    print("Someone tried to forge this token!")
except TempIDFormatError:
    print("Malformed token.")
```

---

## 📝 Real World Examples

### Example 1: Password Reset (Stateless + Payload)
```python
# User clicks "Forgot Password"
tid = TempID.new("15m", payload={"email": user.email})
send_email(user.email, f"https://myapp.com/reset?t={tid.value}")

# When user clicks the link
verified = TempID.verify(request.args["t"])
if verified:
    reset_password(verified.payload["email"], new_password)
```

### Example 2: One-Time-Password (OTP / Burn-After-Reading)
```python
configure(store=RedisBackend("redis://localhost"))

# Create 1-time use OTP
otp = TempID.new("5m", max_uses=1)
send_sms(user.phone, otp.value)

# Verify
verified = TempID.verify(user_input, check_uses=True)
if verified and verified.use():
    login_user()
else:
    print("Invalid or already used OTP!")
```

---

## 🤝 Backward Compatibility
`tempid` is fully backward compatible with legacy v1 tokens (`XXXX-XXXX-XXXX`). Passing a v1 token to `TempID.from_string()` will parse it seamlessly.

## 📄 License
MIT © 2026 Rahul Vachhani
