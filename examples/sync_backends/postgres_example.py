from tempid import configure, TempID, teardown
from tempid.backends import PostgreSQLBackend

configure(
    store=PostgreSQLBackend(
        dsn="postgresql://user:password@localhost:5432/mydb",
        min_conn=1,
        max_conn=10,
    )
)

token = TempID.new("30d", payload={"plan": "trial"}, max_uses=100)
print(token.value)

verified = TempID.verify(token.value, check_uses=True)
if verified:
    print(verified.use())  # True
    print(verified.uses_info())  # {'total': 100, 'used': 1, 'left': 99}

teardown()
