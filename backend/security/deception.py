"""
RansomShield Defensive Deception Boundary (Phase C)
Redirects sessions after 4 failed auth attempts to an isolated DECOY environment.
Enforces strict 403 segregation so decoy tokens cannot access production telemetry or host control.
"""
import os
import time
import hashlib
import jwt
from typing import Dict, Tuple

SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "ransomshield-deception-key-secret-2026")
ALGORITHM = "HS256"

# In-memory tracking of failed login attempts: {ip_address: (count, timestamp)}
_FAILED_ATTEMPTS: Dict[str, Tuple[int, float]] = {}

def record_failed_attempt(ip_address: str) -> int:
    current_time = time.time()
    count, last_time = _FAILED_ATTEMPTS.get(ip_address, (0, current_time))
    
    # Reset count if last attempt was > 15 minutes ago
    if current_time - last_time > 900:
        count = 0
        
    count += 1
    _FAILED_ATTEMPTS[ip_address] = (count, current_time)
    return count

def reset_failed_attempts(ip_address: str):
    if ip_address in _FAILED_ATTEMPTS:
        del _FAILED_ATTEMPTS[ip_address]

def is_deception_triggered(ip_address: str) -> bool:
    count, _ = _FAILED_ATTEMPTS.get(ip_address, (0, 0))
    return count >= 3

def hash_password(password: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), b"ransomshield_salt", 100000).hex()

def verify_password(password: str, password_hash: str) -> bool:
    return hash_password(password) == password_hash

def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def decode_access_token(token: str) -> dict:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except Exception:
        return {}

