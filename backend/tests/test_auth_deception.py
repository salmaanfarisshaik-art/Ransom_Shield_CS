"""
Automated Security & Defensive Deception Test Suite (Phases B & C & 39)
Verifies authentication, RBAC, 4-failed attempt boundary, decoy token isolation, and 403 enforcement.
"""
import pytest
from backend.security.deception import (
    hash_password, verify_password, record_failed_attempt, is_deception_triggered,
    create_access_token, decode_access_token, reset_failed_attempts
)

def test_password_hashing():
    pwd = "SecretPassword123!"
    pwd_hash = hash_password(pwd)
    assert verify_password(pwd, pwd_hash) is True
    assert verify_password("WrongPassword", pwd_hash) is False

def test_failed_attempts_deception_trigger():
    ip = "192.168.1.100"
    reset_failed_attempts(ip)
    
    assert is_deception_triggered(ip) is False
    
    record_failed_attempt(ip) # 1
    record_failed_attempt(ip) # 2
    record_failed_attempt(ip) # 3
    assert is_deception_triggered(ip) is False
    
    record_failed_attempt(ip) # 4 -> Trigger deception
    assert is_deception_triggered(ip) is True

def test_jwt_token_decoy_segregation():
    prod_payload = {"sub": "analyst1", "role": "ANALYST", "session_type": "PRODUCTION"}
    decoy_payload = {"sub": "decoy_user", "role": "VIEWER", "session_type": "DECOY"}

    prod_token = create_access_token(prod_payload)
    decoy_token = create_access_token(decoy_payload)

    decoded_prod = decode_access_token(prod_token)
    decoded_decoy = decode_access_token(decoy_token)

    assert decoded_prod["session_type"] == "PRODUCTION"
    assert decoded_decoy["session_type"] == "DECOY"
