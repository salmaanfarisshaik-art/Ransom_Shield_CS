"""
RansomShield Auth Routes — Login, Register, Admin Approval, Honeypot
"""
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from typing import Optional
from datetime import datetime
import uuid

from backend.security.deception import (
    hash_password, verify_password,
    record_failed_attempt, is_deception_triggered,
    create_access_token, reset_failed_attempts
)

auth_router = APIRouter()

# ── In-memory user store ────────────────────────────────────────────────────
# Format: {username: {password_hash, role, status, email, created_at, approved_by}}
_USERS: dict = {
    "admin": {
        "password_hash": hash_password("admin123"),
        "role": "ADMIN",
        "status": "APPROVED",
        "email": "admin@ransomshield.local",
        "created_at": datetime.utcnow().isoformat(),
        "approved_by": "SYSTEM"
    }
}

# Honeypot session tokens (fake tokens for attackers)
_HONEYPOT_TOKENS: set = set()

# ── Schemas ─────────────────────────────────────────────────────────────────
class RegisterRequest(BaseModel):
    username: str
    password: str
    email: Optional[str] = ""
    full_name: Optional[str] = ""

class LoginRequest(BaseModel):
    username: str
    password: str


# ── REGISTER ────────────────────────────────────────────────────────────────
@auth_router.post("/api/auth/register")
async def register(payload: RegisterRequest, request: Request):
    uname = payload.username.strip().lower()
    if not uname or len(uname) < 3:
        raise HTTPException(status_code=400, detail="Username must be at least 3 characters")
    if uname in _USERS:
        raise HTTPException(status_code=409, detail="Username already exists")
    if len(payload.password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")

    _USERS[uname] = {
        "password_hash": hash_password(payload.password),
        "role": "ANALYST",
        "status": "PENDING",          # Requires admin approval
        "email": payload.email,
        "full_name": payload.full_name,
        "created_at": datetime.utcnow().isoformat(),
        "approved_by": None
    }
    return {
        "status": "PENDING_APPROVAL",
        "message": "Registration successful. Your account is pending admin approval. You will be notified once approved.",
        "username": uname
    }


# ── LOGIN ────────────────────────────────────────────────────────────────────
@auth_router.post("/api/auth/login")
async def login(payload: LoginRequest, request: Request):
    ip = request.client.host if request.client else "unknown"
    uname = payload.username.strip().lower()
    user = _USERS.get(uname)

    # Special Admin override: If authenticating with valid ADMIN credentials, reset deception lock
    if user and user.get("role") == "ADMIN" and verify_password(payload.password, user["password_hash"]):
        reset_failed_attempts(ip)
        token = create_access_token({
            "sub": uname,
            "role": user["role"],
            "email": user.get("email", ""),
            "iat": int(datetime.utcnow().timestamp())
        })
        return {
            "access_token": token,
            "token_type": "bearer",
            "role": user["role"],
            "username": uname,
            "honeypot": False,
            "redirect": "/dashboard.html"
        }

    # Check if honeypot already triggered for this IP
    if is_deception_triggered(ip):
        # Issue a HONEYPOT token — attacker thinks they logged in
        fake_token = f"HONEYPOT-{uuid.uuid4().hex}"
        _HONEYPOT_TOKENS.add(fake_token)
        return {
            "access_token": fake_token,
            "token_type": "bearer",
            "role": "ANALYST",
            "username": uname,
            "honeypot": True,          # Frontend uses this to redirect
            "redirect": "/honeypot.html"
        }

    # Lookup user for normal login
    if not user or not verify_password(payload.password, user["password_hash"]):
        fail_count = record_failed_attempt(ip)
        remaining = max(0, 3 - fail_count)
        if is_deception_triggered(ip):
            # Just hit the threshold — next login goes to honeypot
            raise HTTPException(
                status_code=401,
                detail={
                    "error": "HONEYPOT_ARMED",
                    "message": "Invalid credentials. Security threshold reached.",
                    "remaining_attempts": 0,
                    "honeypot_armed": True
                }
            )
        raise HTTPException(
            status_code=401,
            detail={
                "error": "INVALID_CREDENTIALS",
                "message": f"Invalid username or password. {remaining} attempt(s) remaining before lockout.",
                "remaining_attempts": remaining,
                "fail_count": fail_count
            }
        )

    # Check approval status
    if user["status"] == "PENDING":
        raise HTTPException(
            status_code=403,
            detail={
                "error": "PENDING_APPROVAL",
                "message": "Your account is pending admin approval. Please wait for an administrator to activate your account."
            }
        )
    if user["status"] == "REJECTED":
        raise HTTPException(status_code=403, detail={"error": "ACCOUNT_REJECTED", "message": "Your account has been rejected by the administrator."})
    if user["status"] == "SUSPENDED":
        raise HTTPException(status_code=403, detail={"error": "ACCOUNT_SUSPENDED", "message": "Your account has been suspended. Contact the administrator."})

    # Successful login — reset failed attempts, issue real token
    reset_failed_attempts(ip)
    token = create_access_token({
        "sub": uname,
        "role": user["role"],
        "email": user.get("email", ""),
        "iat": int(datetime.utcnow().timestamp())
    })
    return {
        "access_token": token,
        "token_type": "bearer",
        "role": user["role"],
        "username": uname,
        "honeypot": False,
        "redirect": "/dashboard.html"
    }


def _extract_token_payload(request: Request) -> dict:
    auth_header = request.headers.get("authorization") or request.headers.get("x-api-key") or ""
    token = auth_header.replace("Bearer ", "").strip()
    if not token:
        return {}
    from backend.security.deception import decode_access_token
    return decode_access_token(token)


# ── ADMIN: LIST USERS ────────────────────────────────────────────────────────
@auth_router.get("/api/auth/users")
async def list_users(request: Request):
    payload = _extract_token_payload(request)
    auth_header = request.headers.get("authorization") or request.headers.get("x-api-key") or ""
    token = auth_header.replace("Bearer ", "").strip()
    if payload.get("role") != "ADMIN" and token != "changeme-in-production":
        raise HTTPException(status_code=403, detail="Admin access required")
    return {
        "users": [
            {
                "username": u,
                "role": d["role"],
                "status": d["status"],
                "email": d.get("email", ""),
                "full_name": d.get("full_name", ""),
                "created_at": d.get("created_at", ""),
                "approved_by": d.get("approved_by")
            }
            for u, d in _USERS.items()
        ],
        "total": len(_USERS),
        "pending": sum(1 for d in _USERS.values() if d["status"] == "PENDING")
    }


# ── ADMIN: APPROVE USER ──────────────────────────────────────────────────────
@auth_router.post("/api/auth/approve/{username}")
async def approve_user(username: str, request: Request):
    payload = _extract_token_payload(request)
    auth_header = request.headers.get("authorization") or request.headers.get("x-api-key") or ""
    token = auth_header.replace("Bearer ", "").strip()
    if payload.get("role") != "ADMIN" and token != "changeme-in-production":
        raise HTTPException(status_code=403, detail="Admin access required")
    uname = username.strip().lower()
    if uname not in _USERS:
        raise HTTPException(status_code=404, detail=f"User '{uname}' not found")
    approver = payload.get("sub", "admin")
    _USERS[uname]["status"] = "APPROVED"
    _USERS[uname]["approved_by"] = approver
    return {"status": "APPROVED", "username": uname, "approved_by": approver}


# ── ADMIN: REJECT USER ───────────────────────────────────────────────────────
@auth_router.post("/api/auth/reject/{username}")
async def reject_user(username: str, request: Request):
    token = request.headers.get("x-api-key") or request.headers.get("Authorization", "").replace("Bearer ", "")
    from backend.security.deception import decode_access_token
    payload = decode_access_token(token)
    if payload.get("role") != "ADMIN" and token != "changeme-in-production":
        raise HTTPException(status_code=403, detail="Admin access required")
    uname = username.strip().lower()
    if uname not in _USERS:
        raise HTTPException(status_code=404, detail=f"User '{uname}' not found")
    _USERS[uname]["status"] = "REJECTED"
    return {"status": "REJECTED", "username": uname}


# ── ADMIN: SUSPEND USER ──────────────────────────────────────────────────────
@auth_router.post("/api/auth/suspend/{username}")
async def suspend_user(username: str, request: Request):
    token = request.headers.get("x-api-key") or request.headers.get("Authorization", "").replace("Bearer ", "")
    from backend.security.deception import decode_access_token
    payload = decode_access_token(token)
    if payload.get("role") != "ADMIN" and token != "changeme-in-production":
        raise HTTPException(status_code=403, detail="Admin access required")
    uname = username.strip().lower()
    if uname not in _USERS:
        raise HTTPException(status_code=404, detail=f"User '{uname}' not found")
    _USERS[uname]["status"] = "SUSPENDED"
    return {"status": "SUSPENDED", "username": uname}


# ── VERIFY TOKEN ─────────────────────────────────────────────────────────────
@auth_router.get("/api/auth/verify")
async def verify_token(request: Request):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token:
        raise HTTPException(status_code=401, detail="No token provided")
    if token in _HONEYPOT_TOKENS:
        return {"valid": True, "honeypot": True, "role": "ANALYST"}
    from backend.security.deception import decode_access_token
    payload = decode_access_token(token)
    if not payload or "sub" not in payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return {"valid": True, "honeypot": False, "username": payload["sub"], "role": payload.get("role", "ANALYST")}


# ── LOGOUT ───────────────────────────────────────────────────────────────────
@auth_router.post("/api/auth/logout")
async def logout(request: Request):
    return {"status": "LOGGED_OUT", "message": "Session cleared. Please login again."}
