<div align="center">

# tempid

**A link or code that expires on its own — and can be set to work only N times.**

[![PyPI version](https://img.shields.io/pypi/v/tempid.svg)](https://pypi.org/project/tempid/)
[![Python versions](https://img.shields.io/pypi/pyversions/tempid.svg)](https://pypi.org/project/tempid/)
[![License](https://img.shields.io/pypi/l/tempid.svg)](https://github.com/VachhaniRahul/TempID-PyPI-Repo/blob/main/LICENSE)
[![Downloads](https://img.shields.io/pypi/dm/tempid.svg)](https://pypi.org/project/tempid/)

</div>

---

## In plain English

Think about a few things you've used before:

- A **password reset link** that stops working after 15 minutes
- An **invite link** that lets exactly 50 people join, then closes
- A **one-time download link** someone sends you for a file
- An **OTP code** texted to your phone that only works once, for 5 minutes

All of these are the same idea: *something temporary, that should stop working after a time limit or a use limit.*

`tempid` is a small tool developers use to build exactly that, in a few lines of code, without setting up extra infrastructure just for this one feature. If you're not a developer, the rest of this README probably isn't for you — but now you know what the people building your favorite apps reach for when they need a link or code that "expires."

If you *are* a developer, here's the real documentation.

---

## Table of contents

- [Quickstart (5 minutes)](#quickstart-5-minutes)
- [Learn tempid, one method at a time](#learn-tempid-one-method-at-a-time)
- [Why tempid instead of JWT or a database table](#why-tempid-instead-of-jwt-or-a-database-table)
- [How tempid actually works](#how-tempid-actually-works)
- [Real use cases, with full working code](#real-use-cases-with-full-working-code)
- [Every backend, explained](#every-backend-explained)
- [Middleware - protect routes automatically](#middleware---protect-routes-automatically)
- [Async support](#async-support-end-to-end)
- [Full API reference](#full-api-reference)
- [Security model, explained simply](#security-model-explained-simply)
- [Frequently asked questions](#frequently-asked-questions)
- [Getting help](#getting-help)

---

## Quickstart (5 minutes)

### Step 1 — Install

```bash
pip install tempid
```

One dependency (`cryptography`), which you almost certainly already have.

### Step 2 — Set a secret key

```bash
export TEMPID_SECRET="$(python -c 'import secrets; print(secrets.token_hex(32))')"
```

This is the key tempid uses to sign and encrypt every token. Skip this for quick local testing — tempid will warn you and use a fallback key — but **never skip it in production**, or anyone reading your source code could forge tokens.

### Step 3 — Make a token

```python
from tempid import TempID

tid = TempID.new("15m", payload={"user_id": 42})
print(tid)
# TEMP-V2.AIAGU-Q4CGH-GINNF.QE3QB-WPWBI-PGRQ2.HPGZ5-S4JLD-ZTDVD

link = f"https://yourapp.com/reset?token={tid}"
```

### Step 4 — Verify it later

```python
tid = TempID.verify(request.args["token"])

if tid is None:
    return "This link is invalid or expired.", 400

user_id = tid.payload["user_id"]
```

That's a full expiring-token system. Zero infrastructure. If you also want **"this can only be used N times,"** keep reading — it's one extra argument.

---

## Learn tempid, one method at a time

This section walks through **every method, one at a time** — what you pass in, what you get back, and what it actually prints. No assumptions, no skipped steps. If you're new to Python or new to tempid, start here and run each example yourself.

> Run these in a Python shell (`python3`) one block at a time, in order — later examples build on tokens created in earlier ones.

### `TempID.new()` — create a token

```python
>>> from tempid import TempID
>>> tid = TempID.new("15m")
>>> tid
TempID('TEMP-V2.AIAGU-Q4CGH-GINNF.HPGZ5-S4JLD-ZTDVD', valid, remaining=14m 59s)
```

**What just happened:** `TempID.new("15m")` created a new token that will stop being valid in 15 minutes. The string `"15m"` means *15 minutes*. You can also use `"30s"` (seconds), `"2h"` (hours), or `"7d"` (days).

`tid` is now an object — not just a string. Printing it (as Python does automatically when you type `tid` in the shell) shows you its current status and time remaining, which is handy for debugging.

---

### `print(tid)` — get the actual token string

```python
>>> print(tid)
TEMP-V2.AIAGU-Q4CGH-GINNF.HPGZ5-S4JLD-ZTDVD
```

**What just happened:** This is the actual string you'd put in a URL or send in an email. It's what `str(tid)` returns, and it's what `print()` shows by default for any tempid token. Save this — you'll need it for the next example.

---

### `tid.valid()` — check if it's still good

```python
>>> tid.valid()
True
```

**What just happened:** Returns `True` because we created this token seconds ago with a 15-minute expiry. If you waited 16 minutes and called this again, it would return `False`.

```python
>>> short_lived = TempID.new("1s")
>>> import time
>>> time.sleep(2)
>>> short_lived.valid()
False
```

**What just happened:** We made a token that expires in 1 second, waited 2 seconds, then checked. It correctly returned `False`.

---

### `tid.expired()` — the opposite of `valid()`

```python
>>> tid.expired()
False
>>> short_lived.expired()
True
```

**What just happened:** `expired()` always returns the opposite of `valid()`. It exists purely so your code can read naturally — `if tid.expired(): ...` is clearer than `if not tid.valid(): ...` in some contexts. Use whichever reads better in your code.

---

### `tid.remaining()` — human-readable time left

```python
>>> tid.remaining()
'14m 52s'
```

**What just happened:** Returns a short string showing time left, automatically choosing the right format:

```python
>>> TempID.new("45s").remaining()
'45s'
>>> TempID.new("90m").remaining()
'1h 30m'
>>> TempID.new("3d").remaining()
'3d 0h'
>>> short_lived.remaining()
'expired'
```

**What just happened:** Seconds-only for under a minute, `"Xm Ys"` for under an hour, `"Xh Ym"` for under a day, `"Xd Yh"` beyond that. Once a token has expired, this always returns the literal string `'expired'`.

---

### `TempID.verify()` — the safe way to check a token someone sends you

```python
>>> token_string = "TEMP-V2.AIAGU-Q4CGH-GINNF.HPGZ5-S4JLD-ZTDVD"
>>> result = TempID.verify(token_string)
>>> result
TempID('TEMP-V2.AIAGU-Q4CGH-GINNF.HPGZ5-S4JLD-ZTDVD', valid, remaining=14m 31s)
```

**What just happened:** `verify()` takes a raw string (exactly what a user would paste into a URL) and gives you back a usable `TempID` object — *if* it's genuine and not expired. This is what you call when a request comes in from outside your code.

```python
>>> TempID.verify("this-is-not-a-real-token")
>>> print(TempID.verify("this-is-not-a-real-token"))
None
```

**What just happened:** Garbage input returns `None` — it never raises an error. This is the whole point of `verify()`: you can always safely write `if TempID.verify(token):` without wrapping it in a `try/except`.

```python
>>> tampered = token_string[:-1] + "X"   # change the very last character
>>> print(TempID.verify(tampered))
None
```

**What just happened:** Even changing a single character breaks the signature, so `verify()` rejects it — again, returning `None` instead of raising.

---

### `TempID.from_string()` — the strict version of `verify()`

```python
>>> tid2 = TempID.from_string(token_string)
>>> tid2
TempID('TEMP-V2.AIAGU-Q4CGH-GINNF.HPGZ5-S4JLD-ZTDVD', valid, remaining=14m 10s)
```

**What just happened:** Same idea as `verify()`, but for a valid token it behaves the same. The difference shows up with *invalid* input:

```python
>>> TempID.from_string("garbage-token")
Traceback (most recent call last):
  ...
tempid.exceptions.TempIDFormatError: Invalid V2 token format: 'garbage-token'
```

**What just happened:** Unlike `verify()`, `from_string()` *raises an exception* instead of quietly returning `None`. Use `from_string()` only if you specifically want to catch and handle different failure reasons (`TempIDFormatError` vs `TempIDTamperedError`) separately. For everyday use, prefer `verify()`.

---

### `payload={...}` — attaching your own data to a token

```python
>>> tid3 = TempID.new("10m", payload={"user_id": 42, "email": "demo@example.com"})
>>> tid3.payload
{'user_id': 42, 'email': 'demo@example.com'}
```

**What just happened:** Anything JSON-serializable (numbers, strings, lists, nested dicts) can be attached as `payload`. It's compressed and encrypted into the token itself — there's no separate database lookup needed to get this data back.

```python
>>> str(tid3)
'TEMP-V2.AIAGU-...much-longer-string-here...VYR5U'
>>> recovered = TempID.verify(str(tid3))
>>> recovered.payload
{'user_id': 42, 'email': 'demo@example.com'}
```

**What just happened:** We turned the token into a string (as if sending it in a URL), then verified it back — and the payload came through intact. This proves the payload travels *inside* the token string itself.

```python
>>> print(TempID.new("10m").payload)
None
```

**What just happened:** If you don't pass `payload`, `tid.payload` is simply `None`. There's no payload section in the token string at all in that case (the token is shorter).

---

### `max_uses=...` and `tid.use()` — limiting how many times a token works

This one needs a backend configured first, because something has to remember "how many times has this been used" between separate calls to your app.

```python
>>> from tempid import configure
>>> from tempid.backends import MemoryBackend
>>> configure(store=MemoryBackend())
```

**What just happened:** `MemoryBackend()` is the simplest possible backend — it just remembers use-counts in a Python dictionary while your program is running. Perfect for trying this out; not suitable for production (more on that further down).

```python
>>> limited = TempID.new("1h", max_uses=2)
>>> limited.use()
True
>>> limited.use()
True
>>> limited.use()
False
```

**What just happened:** We created a token allowed to be used **2 times**. The first two calls to `.use()` returned `True` (allowed). The third call returned `False` — the limit was reached, and tempid blocked it.

```python
>>> limited.uses_info()
{'total': 2, 'used': 2, 'left': 0}
```

**What just happened:** `uses_info()` gives you a snapshot dictionary — handy for showing a user "you've used this 2 of 2 times" without writing that logic yourself.

```python
>>> unlimited = TempID.new("1h")  # no max_uses passed
>>> unlimited.use()
True
>>> unlimited.use()
True
>>> unlimited.uses_info()
{'total': None, 'used': None, 'left': None}
```

**What just happened:** Without `max_uses`, `.use()` always returns `True` instantly — it doesn't even check the backend, because there's no limit to check against.

---

### `check_uses=True` — checking the limit without consuming a use

```python
>>> still_has_uses = TempID.verify(str(limited), check_uses=True)
>>> print(still_has_uses)
None
```

**What just happened:** Remember, `limited` already hit its `max_uses=2` cap above. Passing `check_uses=True` to `verify()` makes it *also* check the backend's use-count — and since the limit was already reached, it returns `None`, just like an expired or tampered token would. Importantly, this check does **not** itself consume a use — it's read-only, so you can call it as many times as you like (e.g. to show "0 uses left" on a page) without affecting the actual count.

---

### `tid.on_expire()` — running code automatically when a token expires

```python
>>> reminder = TempID.new("1s")
>>> reminder.on_expire(lambda: print("This token just expired!"))
TempID('...', valid, remaining=1s)
>>> import time; time.sleep(2)
>>> reminder.valid()
This token just expired!
False
```

**What just happened:** `on_expire()` registers a function to run the *first time* tempid notices the token has expired — which happens the next time you call `.valid()` (or `.expired()`) after the expiry time has passed. Notice the callback printed its message *during* the `.valid()` call, right before it returned `False`. This is useful for cleanup — e.g. deleting a temporary session record the moment it's no longer needed.

---

That's the entire surface area of tempid. Every method you'll ever call is one of the ones above. The rest of this README covers *why* you'd reach for each one, and how to wire `max_uses` into a real production backend like Redis instead of `MemoryBackend`.

---

## Why tempid instead of JWT or a database table

|                                   | Raw JWT             | DIY database table | **tempid**                  |
|-----------------------------------|:--------------------:|:--------------------:|:-----------------------------:|
| Verifies without touching a DB    | Yes                  | No                   | Yes                            |
| Built-in expiry                   | Yes (you wire it up) | Manual               | Yes (automatic)                |
| Payload is actually encrypted     | No — just base64     | Depends on your schema | Yes — AES-GCM                |
| "Use this exactly N times" limit  | No                   | Manual, race-prone   | Yes — built-in, atomic         |
| Tamper detection                  | Yes                  | N/A                  | Yes — HMAC-SHA256              |
| Needs a migration / new table     | No                   | Yes                  | No (unless you want use-limits)|
| Needs a cleanup cron job          | No                   | Yes                  | No                              |

**Honestly:** JWT is built to be a portable identity assertion that multiple independent services can verify on their own — that's a real, useful problem, and JWT is the right tool for it.

A password reset link isn't that. It's a short-lived action token one part of your app issues and another part checks five minutes later. JWT works for that, but you end up hand-rolling claims, remembering payloads are only base64 (readable, not encrypted), and building your own use-count tracking — because JWT doesn't have one.

tempid is built to do that one job well.

---

## How tempid actually works

A token is one string you can put straight into a URL:

```
TEMP-V2.AIAGU-Q4CGH-GINNF.QE3QB-WPWBI-PGRQ2-7DX2U.HPGZ5-S4JLD-ZTDVD
   ^        ^ header           ^ encrypted payload      ^ signature
 version
```

- **Header** — when this token expires, a random nonce so two tokens are never identical, and the use-limit.
- **Payload** *(optional)* — your data (e.g. `{"user_id": 42}`), JSON-encoded, compressed, then encrypted with AES-GCM. Nobody who intercepts this token can read it.
- **Signature** — HMAC-SHA256 over the header and payload. Change one character, verification fails.

`verify()` checks the signature *first*, before decoding anything else. A garbage token gets rejected in microseconds, zero database calls made — so spamming your endpoint with fake tokens can't be used to hammer your database.

---

## Real use cases, with full working code

These are complete, copy-pasteable examples — not fragments.

### 1. Password reset email

```python
from tempid import TempID

# When the user clicks "Forgot password"
tid = TempID.new("15m", payload={"user_id": user.id})
send_email(user.email, link=f"https://app.com/reset?token={tid}")

# When they click the link in their email
tid = TempID.verify(request.args["token"])
if tid is None:
    return "This link has expired. Please request a new one.", 400

show_reset_password_form(user_id=tid.payload["user_id"])
```

### 2. Magic login link (no password typing)

```python
tid = TempID.new("10m", payload={"email": user.email}, max_uses=1)
send_email(user.email, link=f"https://app.com/login?token={tid}")

# When clicked:
tid = TempID.verify(token, check_uses=True)
if tid and tid.use():
    log_in_user(tid.payload["email"])
else:
    return "This link has expired or was already used.", 400
```

### 3. Invite link, usable by up to 50 people, valid for a week

```python
tid = TempID.new("7d", payload={"team_id": 7}, max_uses=50)
invite_link = f"https://app.com/join?token={tid}"
# Post this one link in Slack, an email, a poster — it tracks its own usage.
```

### 4. One-time file download link

```python
tid = TempID.new("1h", payload={"file_id": "abc123"}, max_uses=3)
download_link = f"https://app.com/download?token={tid}"
```

### 5. OTP / 2FA code with attempt limiting

```python
otp_token = TempID.new("5m", payload={"user_id": 42}, max_uses=1)
# Send this token string directly via SMS. 
# It expires in 5 minutes OR after exactly 1 successful login.
```

---

## Using a Database for Strict Limits (`max_uses`)

If you only need tokens to expire after a certain time, you **do not** need a database. 

However, if you want a token to expire after exactly 1 or 5 uses (using `max_uses=...`), `tempid` needs to connect to your database to safely count how many times it was used.

Here is how to configure each type of database. **Important:** Always call `teardown()` when your app shuts down to safely close the database connections!

| Backend | Best for | Survives restart? | Multi-server safe? |
|---|---|:---:|:---:|
| `MemoryBackend` | Local dev, scripts, tests | No | No |
| `SQLiteBackend` | Single-machine apps | Yes | No |
| `RedisBackend` | Production (recommended) | Yes | Yes |
| `PostgreSQLBackend` | Teams already on Postgres | Yes | Yes |
| `MySQLBackend` | Teams already on MySQL | Yes | Yes |
| `MongoBackend` | Teams already on MongoDB | Yes | Yes |

### MemoryBackend (the default — no setup needed)

```python
from tempid import TempID, configure
from tempid.backends import MemoryBackend

configure(store=MemoryBackend())

tid = TempID.new("1h", max_uses=1)
print(tid.use())  # True  — first use, allowed
print(tid.use())  # False — already used, blocked
```

Warning: don't use this with more than one worker process (Gunicorn, Lambda, anything horizontally scaled) — each process has separate memory, so a `max_uses=1` token could be used once per worker.

### SQLiteBackend

```python
from tempid.backends import SQLiteBackend
configure(store=SQLiteBackend("tempid_uses.db"))
```
Use-counts survive a restart, but only works on a single machine.

### RedisBackend (recommended for production)

```bash
pip install "tempid[redis]"
```
```python
from tempid.backends import RedisBackend
configure(store=RedisBackend("redis://localhost:6379"))

tid = TempID.new("15m", max_uses=1)
print(tid.use())  # True
print(tid.use())  # False — atomic, even if two requests race at the exact same moment
```
The check-and-increment happens as one atomic Redis Lua script — no window for a double-click on an email link to slip through.

### PostgreSQLBackend

```bash
pip install "tempid[postgres]"
```
```python
from tempid.backends import PostgreSQLBackend
configure(store=PostgreSQLBackend(dsn="postgresql://user:pass@localhost/myapp"))
```

Pool sizing note: if you expect 100 concurrent requests, set `max_conn` to at least that, or you'll see `PoolError` from requests that couldn't get a connection.

### MySQLBackend

```bash
pip install "tempid[mysql]"
```
```python
from tempid.backends import MySQLBackend
configure(store=MySQLBackend(host="localhost", user="root", password="...", db="myapp"))
```

### MongoBackend

```bash
pip install "tempid[mongo]"
```
```python
from tempid.backends import MongoBackend
configure(store=MongoBackend("mongodb://localhost:27017", db="myapp"))
```

---

## Middleware — protect routes automatically

### Flask

```python
from functools import wraps
from flask import Flask, request, jsonify
from tempid import TempID, configure
from tempid.backends import RedisBackend

app = Flask(__name__)
configure(store=RedisBackend("redis://localhost:6379"))


def limited_use_token(check_uses=True):
    def decorator(view_func):
        @wraps(view_func)
        def wrapped(*args, **kwargs):
            token = request.args.get("token") or request.headers.get("X-Token")
            if not token:
                return jsonify({"error": "Missing token"}), 401

            tid = TempID.verify(token, check_uses=check_uses)
            if tid is None:
                return jsonify({"error": "Token is invalid, expired, or already used"}), 401

            if tid.max_uses > 0 and not tid.use():
                return jsonify({"error": "Token has reached its use limit"}), 401

            request.tempid = tid
            return view_func(*args, **kwargs)
        return wrapped
    return decorator


@app.route("/reset-password", methods=["POST"])
@limited_use_token()
def reset_password():
    user_id = request.tempid.payload["user_id"]
    return jsonify({"status": "password reset successful"})
```

### FastAPI

```python
from fastapi import FastAPI, Depends, HTTPException, Query
from tempid import TempID, configure
from tempid.async_backends import AsyncRedisBackend

app = FastAPI()
configure(store=AsyncRedisBackend("redis://localhost:6379"))


async def verified_token(token: str = Query(...)) -> TempID:
    tid = await TempID.verify_async(token, check_uses=True)
    if tid is None:
        raise HTTPException(status_code=401, detail="Token is invalid, expired, or already used")
    if tid.max_uses > 0 and not await tid.use_async():
        raise HTTPException(status_code=401, detail="Token has reached its use limit")
    return tid


@app.post("/reset-password")
async def reset_password(tid: TempID = Depends(verified_token)):
    user_id = tid.payload["user_id"]
    return {"status": "password reset successful"}
```

### Django

```python
from functools import wraps
from django.http import JsonResponse
from tempid import TempID, configure
from tempid.backends import PostgreSQLBackend

configure(store=PostgreSQLBackend(dsn="postgresql://user:pass@localhost/myapp"))


def limited_use_token(view_func):
    @wraps(view_func)
    def wrapped(request, *args, **kwargs):
        token = request.GET.get("token") or request.headers.get("X-Token")
        if not token:
            return JsonResponse({"error": "Missing token"}, status=401)

        tid = TempID.verify(token, check_uses=True)
        if tid is None:
            return JsonResponse({"error": "Token is invalid, expired, or already used"}, status=401)

        if tid.max_uses > 0 and not tid.use():
            return JsonResponse({"error": "Token has reached its use limit"}, status=401)

        request.tempid = tid
        return view_func(request, *args, **kwargs)
    return wrapped


@limited_use_token
def reset_password(request):
    user_id = request.tempid.payload["user_id"]
    return JsonResponse({"status": "password reset successful"})
```

---

## Async support, end to end

```python
from tempid import TempID, configure
from tempid.async_backends import AsyncRedisBackend

configure(store=AsyncRedisBackend("redis://localhost:6379"))

async def handle_reset(token: str):
    tid = await TempID.verify_async(token, check_uses=True)
    if tid is None:
        return error_response()
    if not await tid.use_async():
        return error_response("Already used")
    return success_response(tid.payload)
```

```bash
pip install "tempid[async-redis]"     # AsyncRedisBackend
pip install "tempid[async-sqlite]"    # AsyncSQLiteBackend
pip install "tempid[async-mongo]"     # AsyncMongoBackend
pip install "tempid[async-mysql]"     # AsyncMySQLBackend
pip install "tempid[async-postgres]"  # AsyncPostgreSQLBackend
```

Mixing sync and async by accident is caught for you:

```python
tid.use()
# RuntimeError: Configured backend is async. Use 'await tid.use_async()' instead.
```

---

## Full API reference

### Creating tokens

```python
TempID.new(
    expires_in: str = "10m",      # "30s", "10m", "2h", "7d"
    payload: dict | None = None,  # JSON-serializable dict, up to 512 bytes once serialized
    max_uses: int = 0,            # 0 = unlimited, 1-255 = limited
) -> TempID
```

### Reading tokens back

```python
TempID.from_string(value: str) -> TempID
```
Raises `TempIDFormatError` or `TempIDTamperedError` if invalid — use this if you want to handle errors yourself.

```python
TempID.verify(value: str, check_uses: bool = False) -> TempID | None
```
Never raises — returns `None` for any failure. `check_uses=True` confirms the limit hasn't been hit (read-only, doesn't consume a use).

```python
TempID.verify_async(value: str, check_uses: bool = False) -> TempID | None
```
Async version, requires an async backend configured.

### Checking state

```python
tid.valid() -> bool
tid.expired() -> bool
tid.remaining() -> str   # "14m 59s", "2h 3m", "6d 23h", or "expired"
```

### Consuming uses

```python
tid.use() -> bool                 # True if allowed, False if limit reached
tid.use_async() -> bool           # async version

tid.uses_info() -> dict           # {"total": 3, "used": 1, "left": 2}
tid.uses_info_async() -> dict     # async version
```

### Expiry callbacks

```python
tid.on_expire(callback: Callable[[], None]) -> TempID
tid.on_expire(cleanup_session).on_expire(log_expiry)  # chainable
```

### Configuring a backend

```python
from tempid import configure
configure(store=SomeBackend(...))  # call once, at app startup
```

---

## Security model, explained simply

- **Every token is signed with HMAC-SHA256** — change one character, verification fails.
- **Every payload is encrypted with AES-GCM**, the same authenticated encryption family used in TLS. Not just encoded — genuinely unreadable without the secret.
- **Signature is checked before anything else is decoded** — forged tokens are rejected instantly, with zero database calls.
- **Your secret lives in one environment variable:**
  ```bash
  export TEMPID_SECRET="$(python -c 'import secrets; print(secrets.token_hex(32))')"
  ```
  If unset, tempid warns once and falls back to an insecure default — fine for local dev, never for production.

---

## Frequently asked questions

**Is this a replacement for JWT?**
For short-lived, single-purpose action tokens — yes, and simpler. For identity assertions verified independently across multiple services, JWT is still the right call.

**Do I need a database at all?**
Not for expiry, signing, or encrypted payloads — those live entirely inside the token string. Only `max_uses` needs a backend.

**What if I forget to set `TEMPID_SECRET`?**
One `UserWarning`, then an insecure fallback. Works for local testing — never deploy to production without setting it.

**Can this run across multiple servers?**
Always, for expiry-only tokens. For `max_uses` tokens, use anything except `MemoryBackend`.

**How big can the payload be?**
Up to 512 bytes after JSON serialization — enough for IDs or emails, not for storing actual data. Treat it as a pointer (`{"user_id": 42}`), not a database.

**Is this production-ready?**
Yes — every use-count backend has been stress-tested at 1,000 concurrent requests against a strict `max_uses` limit, with the limit enforced exactly every time, no double-spending, on every backend.

---

## Getting help

- Found a bug? [Open an issue](https://github.com/VachhaniRahul/TempID-PyPI-Repo/issues) with a small reproducible snippet if you can.
- Have an idea or a question? Issues are fine for those too.
- Something here confusing? That's on the docs, not on you — tell us and we'll fix it.

## Contributing

1. Open an issue first for anything beyond a small fix.
2. Run `pytest` before submitting.
3. New backends or features should come with a matching README section.

## License

MIT — see [LICENSE](https://github.com/VachhaniRahul/TempID-PyPI-Repo/blob/main/LICENSE).

---

<div align="center">

**If tempid saved you from writing yet another tokens table and a cleanup cron job, a star on the repo helps other developers find it.**

</div>