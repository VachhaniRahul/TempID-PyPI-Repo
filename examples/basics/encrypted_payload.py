from tempid import TempID

token = TempID.new("1h", payload={"user_id": 42, "email": "hello@example.com"})
print(token.value)

verified = TempID.verify(token.value)
if verified:
    print(verified.payload["user_id"])  # 42
    print(verified.payload["email"])    # hello@example.com
