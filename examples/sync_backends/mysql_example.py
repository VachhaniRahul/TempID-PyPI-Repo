from tempid import configure, TempID, teardown
from tempid.backends import MySQLBackend

configure(store=MySQLBackend(
    host="127.0.0.1",
    port=3306,
    user="root",
    password="your_password",
    db="mydb",
))

token = TempID.new("7d", max_uses=5)
print(token.value)

verified = TempID.verify(token.value, check_uses=True)
if verified:
    print(verified.use())        # True
    print(verified.uses_info())  # {'total': 5, 'used': 1, 'left': 4}

teardown()
