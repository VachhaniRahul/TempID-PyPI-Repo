from tempid import configure, TempID, teardown
from tempid.backends import MongoBackend

configure(store=MongoBackend("mongodb://localhost:27017", "mydb"))

token = TempID.new("1h", payload={"doc_id": "report-q4.pdf"}, max_uses=1)
print(token.value)

verified = TempID.verify(token.value, check_uses=True)
if verified:
    if verified.use():
        print("Download allowed! Doc:", verified.payload["doc_id"])
    else:
        print("Already downloaded!")

teardown()
