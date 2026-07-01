import os
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from tempid import TempID

os.environ.setdefault("TEMPID_SECRET", "your-secret-key-here")

# No database needed — expiry is locked inside the token itself.

app = FastAPI(title="Forgot Password — TempID Demo")


class ForgotPasswordRequest(BaseModel):
    email: str


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str


@app.post("/auth/forgot-password")
async def forgot_password(req: ForgotPasswordRequest):
    token = TempID.new("15m", payload={"email": req.email})
    reset_link = f"https://myapp.com/reset-password?token={token.value}"

    # Replace with your actual email sender (SendGrid, SES, SMTP, etc.)
    # await send_email(req.email, reset_link)

    return {
        "message": f"Reset link sent to {req.email}",
        "expires_in": token.remaining(),
        "_debug_link": reset_link,
    }


@app.post("/auth/reset-password")
async def reset_password(req: ResetPasswordRequest):
    verified = TempID.verify(req.token)

    if not verified:
        raise HTTPException(400, "Link is invalid or has expired. Please request a new one.")

    email = verified.payload["email"]

    # Replace with your actual DB password update logic
    # await db.update_password(email, hash(req.new_password))

    return {"success": True, "message": f"Password updated for {email}"}


# Run: uvicorn forgot_password:app --reload
