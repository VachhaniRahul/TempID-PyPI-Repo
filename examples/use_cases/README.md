# use_cases

End-to-end FastAPI examples showing how TempID fits into real application flows.

| File | Use Case |
|------|----------|
| `api_access_middleware.py` | Issue a trial API key with a max request limit. `Authorization` header is validated on every request. |
| `forgot_password.py` | Generate a 15-min password reset link. Verify and reset on link click. No database needed. |

**Install:**
```bash
pip install "tempid[redis]" fastapi uvicorn
```

**Run:**
```bash
uvicorn api_access_middleware:app --reload
uvicorn forgot_password:app --reload
```

**Test API middleware:**
```bash
# Issue a key
curl -X POST http://localhost:8000/issue-api-key \
  -H "Content-Type: application/json" \
  -d '{"email": "dev@startup.io", "max_requests": 5}'

# Use the key
curl http://localhost:8000/api/data \
  -H "Authorization: TEMP-V2.YOUR_KEY_HERE"
```

**Test forgot password:**
```bash
# Request reset link
curl -X POST http://localhost:8000/auth/forgot-password \
  -H "Content-Type: application/json" \
  -d '{"email": "alice@company.com"}'

# Reset password using the token from the response
curl -X POST http://localhost:8000/auth/reset-password \
  -H "Content-Type: application/json" \
  -d '{"token": "TEMP-V2.YOUR_TOKEN_HERE", "new_password": "NewPass123!"}'
```
