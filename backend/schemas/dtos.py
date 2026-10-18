"""
Pydantic Schemas / DTOs for RansomShield API Request & Response validation.
"""
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime

class UserRegisterSchema(BaseModel):
    username: str
    password: str
    role: Optional[str] = "ANALYST"

class UserLoginSchema(BaseModel):
    username: str
    password: str

class TokenResponseSchema(BaseModel):
    access_token: str
    token_type: str = "bearer"
    session_type: str = "PRODUCTION"
    role: str
    username: str

class EndpointRegisterSchema(BaseModel):
    endpoint_id: str
    hostname: str
    os: str
    os_version: Optional[str] = "Windows 11"
    agent_version: Optional[str] = "1.0.0"
    ip_address: Optional[str] = "127.0.0.1"

class ProcessKillRequestSchema(BaseModel):
    process_instance_id: Optional[str] = None
    pid: Optional[int] = None
    reason: Optional[str] = "Manual analyst intervention"

class EndpointIsolateRequestSchema(BaseModel):
    endpoint_id: str
    simulated: bool = True
    reason: Optional[str] = "High risk score containment"

class YARARuleSchema(BaseModel):
    rule_name: str
    rule_content: str

class ReportGenerateRequestSchema(BaseModel):
    incident_id: str
    format: str = "PDF" # PDF, HTML, JSON
