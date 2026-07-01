from tempid import configure, TempID, teardown
from tempid.backends import SQLiteBackend

configure(store=SQLiteBackend("tempid.db"))

token = TempID.new("1h", max_uses=3)
print(token.value)

verified = TempID.verify(token.value, check_uses=True)
if verified:
    print(verified.use())  # True
    print(verified.use())  # True
    print(verified.use())  # True
    print(verified.use())  # False — limit reached
    print(verified.uses_info())  # {'total': 3, 'used': 3, 'left': 0}

teardown()
