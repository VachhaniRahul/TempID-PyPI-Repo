from tempid import configure, TempID, teardown
from tempid.backends import RedisBackend

configure(store=RedisBackend("redis://localhost:6379/0"))

token = TempID.new("5m", max_uses=1)
print(token.value)

verified = TempID.verify(token.value, check_uses=True)
if verified:
    print(verified.use())  # True
    print(verified.use())  # False — limit reached

teardown()
