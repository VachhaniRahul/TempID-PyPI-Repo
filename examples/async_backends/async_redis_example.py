import asyncio
from tempid import configure, TempID, teardown_async
from tempid.async_backends import AsyncRedisBackend


async def main():
    configure(store=AsyncRedisBackend("redis://localhost:6379/0"))

    token = TempID.new("5m", max_uses=2)
    print(token.value)

    verified = await TempID.verify_async(token.value, check_uses=True)
    if verified:
        print(await verified.use_async())  # True
        print(await verified.use_async())  # True
        print(await verified.use_async())  # False — limit reached

    await teardown_async()


asyncio.run(main())
