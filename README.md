# tempid

> Unique IDs that automatically expire — like UUID, but with a TTL.

```python
from tempid import TempID

tid = TempID.new("10m", payload={"user_id": 42})
print(tid.value)       # "TEMP-V2.AIAGU-PSOHJ... (Encrypted!)"
print(tid.valid())     # True
print(tid.remaining()) # "9m 58s"

# Safe, stateless verification
verified = TempID.verify(tid.value)
if verified:
    print(verified.payload["user_id"])  # 42
```

No database. No Redis. No cron jobs. The expiry is **inside the token itself**.

---

## Install

```bash
pip install tempid
```

---

## The Problem It Solves

Every app needs temporary tokens — password resets, invite links, OTPs, game room codes. The usual approach:

```
Generate token → Store in DB with expiry → Check DB on each request → Cleanup expired rows
```

This is boilerplate. `tempid` embeds the expiry **inside the ID itself**, so you need none of that.

---

## Quick Start

```python
from tempid import TempID

# Create an ID that expires in 15 minutes
tid = TempID.new("15m")

# Check validity
tid.valid()      # True
tid.expired()    # False
tid.remaining()  # "14m 59s"

# Restore from string (works across server restarts, different machines)
restored = TempID.from_string(tid.value)
restored.valid()  # True (if not expired)

# Register a callback when it expires
tid.on_expire(lambda: print("Token expired!"))
```

---

## Supported Duration Formats

| Format  | Meaning    |
|---------|------------|
| `"30s"` | 30 seconds |
| `"10m"` | 10 minutes |
| `"2h"`  | 2 hours    |
| `"7d"`  | 7 days     |

---

## Real World Examples

### Password Reset Link

```python
from tempid import TempID

# User clicks "Forgot Password"
tid = TempID.new("15m")
reset_link = f"https://myapp.com/reset?token={tid.value}"
send_email(user.email, reset_link)

# When user opens the link
token = request.args.get("token")
try:
    tid = TempID.from_string(token)
    if tid.valid():
        show_reset_form()
    else:
        show_error("This link has expired. Please request a new one.")
except ValueError:
    show_error("Invalid link.")
```

---

### Invite Links

```python
# Create a 7-day invite
invite = TempID.new("7d")
invite_link = f"https://myapp.com/join?invite={invite.value}"

# When someone joins
try:
    invite = TempID.from_string(request.args["invite"])
    if invite.valid():
        create_account(user)
    else:
        show_error("Invite link has expired.")
except ValueError:
    show_error("Invalid invite link.")
```

---

### Game Room / Lobby Code

```python
# Create room
room_code = TempID.new("1h")
print(f"Share this code: {room_code.value}")

# Player tries to join
try:
    code = TempID.from_string(user_input)
    if code.valid():
        join_room(code.value)
    else:
        print("Room has expired.")
except ValueError:
    print("Invalid room code.")
```

---

### Expiry Callback

```python
tid = TempID.new("10m")

# Chain multiple callbacks
tid.on_expire(lambda: cleanup_session()) \
   .on_expire(lambda: log("token expired"))

# Callbacks fire exactly once, on the first .valid() call after expiry
```

---

## Security

### Setting a Secret (Required for Production)

import os

# Set this before starting your app
os.environ["TEMPID_SECRET"] = "your-super-secret-32-byte-key-here"

## Backward Compatibility
`tempid` v2.0 is fully backward compatible with v1 tokens. If you pass an old `XXXX-XXXX-XXXX` token into `TempID.from_string()`, it will still parse and validate correctly without throwing formatting errors.

If `TEMPID_SECRET` is not set, `tempid` will warn and use an insecure default.  
**Always set this in production.**

Generate a strong secret:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

### How It Works

A3F2C1D4 - 9E7B2F - C8D4E1A2
├───────┘   ├────┘   ├───────┘
encrypted   random   HMAC-SHA256
timestamp   nonce    signature
(hidden)    (unique) (tamper-proof)
## Why `tempid`?

*   **Stateless by Default:** The expiration time is cryptographically signed into the token. You do not need a database to know if a token is expired.
*   **Encrypted Payloads:** Attach JSON dictionaries to your tokens (up to 512 bytes). They are compressed and fully encrypted using a built-in AES-like stream cipher (CTR mode). Users cannot read or modify their payloads.
*   **Human-Readable Formats:** Built using dashed Base32 (e.g. `TEMP-V2.XXXX...`) for a premium, Stripe-like developer experience.
*   **Highly Secure:** Protected by 96-bit HMAC-SHA256 signatures to prevent tampering.
*   **Zero Dependencies:** Just pure Python standard library.

| Attack | Status |
|--------|--------|
| Forge a valid ID without the secret | ✅ Blocked by HMAC |
| Tamper with expiry time | ✅ Blocked by HMAC |
| Read the expiry from the ID | ✅ Blocked by XOR encryption |
| Replay a valid (unexpired) ID | ⚠️ By design — store used IDs in a set/cache if needed |

---

### One-Time Use (Optional)

`tempid` is stateless by design. For one-time-use tokens (e.g. password reset used only once):

```python
used_tokens = set()  # use Redis in production

tid = TempID.from_string(token)
if tid.valid() and token not in used_tokens:
    used_tokens.add(token)
    # ✅ process the request
```

---

## API Reference

### `TempID.new(expires_in)`

Creates a new TempID.

| Parameter    | Type  | Default  | Description                                  |
|--------------|-------|----------|----------------------------------------------|
| `expires_in` | `str` | `"10m"`  | Duration: `"30s"`, `"10m"`, `"2h"`, `"7d"` |

**Returns:** `TempID`  
**Raises:** `ValueError` if duration format is invalid

---

### `TempID.from_string(value)`

Restores a TempID from its string value.

**Returns:** `TempID`  
**Raises:**
- `ValueError` — if the ID is invalid or has been tampered with
- `TypeError` — if value is not a string

---

### `tid.valid()` → `bool`

Returns `True` if the ID has not yet expired. Fires `on_expire` callbacks on first call after expiry.

---

### `tid.expired()` → `bool`

Opposite of `valid()`.

---

### `tid.remaining()` → `str`

Human-readable time remaining.

```python
tid.remaining()  # "9m 45s", "1h 20m", "6d 23h", "expired"
```

---

### `tid.on_expire(callback)` → `TempID`

Register a callback fired once when the ID expires. Returns `self` for chaining.

```python
tid.on_expire(lambda: cleanup()).on_expire(lambda: log("expired"))
```

---

### `tid.value` → `str`

The token string. Safe to store, share in URLs, send in emails.

---

### `tid.expires_at` → `int`

Unix timestamp (seconds) when the ID expires.

---

## Environment Variables

| Variable         | Required             | Description                                                                 |
|------------------|----------------------|-----------------------------------------------------------------------------|
| `TEMPID_SECRET`  | **Yes (production)** | Secret key for HMAC signing and timestamp encryption. Must be the same across all instances. |

---

## When NOT to Use TempID

- **Auth sessions** — use a proper session library (Flask-Login, Django sessions)
- **API keys** — use a dedicated API key management system
- **Payment tokens** — use Stripe / payment provider tokens
- **High-security auth flows** — use JWT with RS256 or a dedicated auth provider

TempID is designed for **lightweight, developer-friendly temporary identifiers** — not as a full authentication system.

---

## Contributing

```bash
git clone https://github.com/VachhaniRahul/TempID-PyPI-Repo
cd TempID-PyPI-Repo
pip install -e ".[dev]"
pytest
```

---

## License

MIT © 2026 Rahul Vachhani
