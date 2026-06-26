# tempid

> Unique IDs that automatically expire. Like UUID, but with a TTL.

```python
from tempid import TempID

tid = TempID.new("10m")
print(tid.value)        # "A3F2C1D4-9E7B2F-C8D4E1A2"
print(tid.valid())      # True
print(tid.remaining())  # "9m 58s"

# 10 minutes later...
print(tid.valid())      # False
```

No database. No Redis. No cron jobs. Just install and use.

---

## Install

```bash
pip install tempid
```

---

## The Problem It Solves

Every app needs temporary tokens — password resets, invite links, OTPs, game room codes, file downloads. The usual approach:

```
Generate token → Store in DB with expiry → Check DB on each request → Cleanup expired rows
```

This is annoying boilerplate. `tempid` embeds the expiry **inside the ID itself**, so you need none of that.

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
restored.valid()   # True (if not expired)

# On expire callback
tid.on_expire(lambda: print("Token expired!"))
```

---

## Supported Duration Formats

| Format | Meaning   |
|--------|-----------|
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
        # ✅ Allow password reset
        show_reset_form()
    else:
        # ❌ Link expired
        show_error("This link has expired. Please request a new one.")
except ValueError:
    show_error("Invalid link.")
```

---

### Email / Phone OTP (No DB Needed)

```python
# Send OTP
tid = TempID.new("5m")
send_sms(user.phone, f"Your code: {tid.value}")
session["otp_token"] = tid.value   # just store in session, not DB

# Verify OTP
try:
    tid = TempID.from_string(session["otp_token"])
    if tid.valid():
        verify_user()
    else:
        show_error("OTP expired. Request a new one.")
except ValueError:
    show_error("Invalid OTP.")
```

---

### Invite Links

```python
# Create a 7-day invite
invite = TempID.new("7d")
invite_link = f"https://myapp.com/join?invite={invite.value}"
share_with_team(invite_link)

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

### Temporary File Download Link

```python
# Generate a 30-minute download link
tid = TempID.new("30m")
download_url = f"https://files.myapp.com/download/{tid.value}"

# When user hits the endpoint
try:
    tid = TempID.from_string(path_param)
    if tid.valid():
        serve_file(filename)
    else:
        return 410  # Gone
except ValueError:
    return 400  # Bad Request
```

---

## Security

### How It Works

Each TempID contains two parts — an **encrypted timestamp** and an **HMAC signature**:

```
A3F2C1D4 - 9E7B2F - C8D4E1A2
├───────┤   ├────┤   ├───────┤
encrypted   random   HMAC-SHA256
timestamp   nonce    signature
(hidden)    (unique) (tamper-proof)
```

- **Encrypted timestamp** — the expiry time is XOR-masked with a secret-derived key, so it's not directly readable
- **Random nonce** — ensures two IDs created at the same second are always different
- **HMAC-SHA256 signature** — 64-bit signature prevents anyone from forging or tampering with an ID

### Setting a Secret (Required for Production)

```bash
export TEMPID_SECRET="your-strong-random-secret-here"
```

If `TEMPID_SECRET` is not set, `tempid` will issue a warning and use an insecure default. **Always set this in production.**

Generate a strong secret:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

### What Attacks Are Prevented

| Attack | Status |
|--------|--------|
| Forge a valid ID without the secret | ✅ Blocked by HMAC |
| Tamper with expiry time | ✅ Blocked by HMAC |
| Read the expiry from the ID | ✅ Blocked by XOR encryption |
| Brute-force the signature | ✅ 64-bit space — ~18 quintillion guesses |
| Replay a valid (unexpired) ID | ⚠️ By design — use once-use tokens (store used IDs in a set/cache) if needed |

### One-Time Use (Optional)

`tempid` is stateless by design. If you need one-time-use tokens (e.g. password reset that can only be used once), track used IDs yourself:

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

```python
tid = TempID.new("10m")
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `expires_in` | `str` | `"10m"` | Duration string: `"30s"`, `"10m"`, `"2h"`, `"7d"` |

**Returns:** `TempID`  
**Raises:** `ValueError` if duration format is invalid

---

### `TempID.from_string(value)`

Restores a TempID from its string value.

```python
tid = TempID.from_string("A3F2C1D4-9E7B2F-C8D4E1A2")
```

**Returns:** `TempID`  
**Raises:**
- `ValueError` — if the ID is invalid or has been tampered with
- `TypeError` — if value is not a string

---

### `tid.valid()` → `bool`

Returns `True` if the ID has not yet expired. Fires `on_expire` callbacks when it transitions to expired.

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

Register a callback fired once when the ID expires (on next `valid()` call after expiry). Returns `self` for chaining.

```python
tid.on_expire(lambda: cleanup()).on_expire(lambda: log("expired"))
```

---

### `tid.value` → `str`

The string representation of the TempID. Safe to store, share in URLs, send in emails.

---

### `tid.expires_at` → `int`

Unix timestamp (seconds) when the ID expires.

---

## TempID vs Alternatives

| Feature | UUID | JWT | TempID |
|---------|------|-----|--------|
| Unique ID | ✅ | ✅ | ✅ |
| Auto-expiry | ❌ | ✅ | ✅ |
| Simple API | ✅ | ❌ | ✅ |
| No DB needed | ✅ | ✅ | ✅ |
| Tamper-proof | ❌ | ✅ | ✅ |
| Hidden expiry | ❌ | ❌ | ✅ |
| Unique per call | ✅ | ✅ | ✅ |
| Zero dependencies | ✅ | ❌ | ✅ |

---

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `TEMPID_SECRET` | **Yes (production)** | Secret key for HMAC signing and timestamp encryption. Must be the same across all instances. |

---

## When NOT to Use TempID

- **Auth sessions** — use a proper session library (e.g. Flask-Login, Django sessions)
- **API keys** — use a dedicated API key management system
- **Payment tokens** — use Stripe / payment provider tokens
- **High-security auth flows** — use JWT with RS256 or a dedicated auth provider

TempID is designed for **lightweight, developer-friendly temporary identifiers** — not as a full authentication system.

---

## Contributing

```bash
git clone https://github.com/yourusername/tempid
cd tempid
pip install -e ".[dev]"
pytest
```

---

## License

MIT © 2025 Your Name
