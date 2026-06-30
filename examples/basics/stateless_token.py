from tempid import TempID

token = TempID.new("15m")
print(token.value)
print(token.remaining())

verified = TempID.verify(token.value)
if verified:
    print("Valid! Time left:", verified.remaining())
else:
    print("Invalid or expired.")
