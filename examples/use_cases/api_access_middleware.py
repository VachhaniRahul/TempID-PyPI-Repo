import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from tempid import configure, TempID, teardown_async
from tempid.async_backends import AsyncRedisBackend

os.environ.setdefault("TEMPID_SECRET", "your-secret-key-here")

PROTECTED_PREFIXES = ("/api/",)  # Only these routes require an API key


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure(store=AsyncRedisBackend(os.environ.get("REDIS_URL", "redis://localhost:6379/0")))
    yield
    await teardown_async()


app = FastAPI(title="API Access Middleware — TempID Demo", lifespan=lifespan)


# ── Middleware ────────────────────────────────────────────────────────────────

@app.middleware("http")
async def api_key_middleware(request: Request, call_next):
    # Skip middleware for non-protected routes
    if not any(request.url.path.startswith(p) for p in PROTECTED_PREFIXES):
        return await call_next(request)

    api_key = request.headers.get("Authorization")
    if not api_key:
        return JSONResponse({"error": "Missing Authorization header"}, status_code=401)

    verified = await TempID.verify_async(api_key, check_uses=True)
    if not verified:
        return JSONResponse({"error": "Invalid or expired API key"}, status_code=401)

    if not await verified.use_async():
        info = verified.uses_info()
        return JSONResponse(
            {"error": f"Request limit reached ({info['used']}/{info['total']})"},
            status_code=429,
        )

    # Attach usage info to request state so handlers can access it
    request.state.api_remaining = verified.uses_info()["left"]
    return await call_next(request)


# ── Routes ────────────────────────────────────────────────────────────────────

class IssueKeyRequest(BaseModel):
    email: str
    max_requests: int = 1000
    validity: str = "30d"


@app.post("/issue-api-key")
async def issue_api_key(req: IssueKeyRequest):
    token = TempID.new(req.validity, payload={"email": req.email}, max_uses=req.max_requests)
    return {"api_key": token.value, "expires_in": token.remaining(), "max_requests": req.max_requests}


@app.get("/api/users")
async def get_users(request: Request):
    return {"data": ["alice", "bob"], "remaining_requests": request.state.api_remaining}


@app.get("/api/products")
async def get_products(request: Request):
    return {"data": ["widget", "gadget"], "remaining_requests": request.state.api_remaining}


@app.get("/health")
async def health():
    return {"status": "ok"}  # No API key needed — not under /api/


# Run: uvicorn api_access_middleware:app --reload
