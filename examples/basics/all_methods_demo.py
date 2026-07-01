"""
TempID — All Methods Demo
==========================
A quick demonstration of every available method in the TempID core class.
Run this script to see what each method outputs.
"""

import time
from tempid import TempID

print("===== 1. Creating a Token =====")
# TempID.new() creates a token.
# You can set an expiry ("10s", "5m", "1h") and an optional payload.
token = TempID.new("15m", payload={"user": "alice"})
print(f"Token string: {token.value}")
print(f"Expires at: {token.expires_at} (Unix Timestamp)")
print(f"Max Uses: {token.max_uses} (0 means unlimited)")
print(f"Payload: {token.payload}")


print("\n===== 2. Checking State =====")
print(f"Is valid? {token.valid()} (True because time hasn't passed)")
print(f"Is expired? {token.expired()}")
print(f"Time left: {token.remaining()}")


print("\n===== 3. Verifying from a String =====")
# When a user sends you a token string, use TempID.verify() to safely parse it.
# It returns a TempID object if valid, or None if invalid/tampered/expired.
verified = TempID.verify(token.value)
if verified:
    print(f"Verification: Successful! Payload is: {verified.payload}")
else:
    print("Verification: Failed!")


print("\n===== 4. Strict Parsing (from_string) =====")
# from_string() parses a token WITHOUT verifying its signature or time limit.
# It will raise an Exception if the string format is completely broken.
parsed = TempID.from_string(token.value)
print(f"Parsed token: {parsed.value[:20]}...")


print("\n===== 5. Uses and Limits =====")
# .use() is used to consume a token limit. If no max_uses was set (0),
# it always returns True instantly without needing a database.
print(f"Can use? {verified.use()} (True because unlimited)")
print(f"Uses Info: {verified.uses_info()}")


print("\n===== 6. Expiry Callbacks =====")
# You can attach a function that runs EXACTLY ONCE when the token expires.
short_token = TempID.new("1s")
short_token.on_expire(lambda: print("\n[CALLBACK RUN] This token just died!"))

print("Waiting 2 seconds for the short token to expire...")
time.sleep(2)
print(f"Checking valid: {short_token.valid()}")  # Triggers the callback above!
