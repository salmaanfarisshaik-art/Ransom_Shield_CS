"""
RansomShield Kali Integration Schemas
Defines request payloads and event data models for controlled lab node interaction.
"""
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from datetime import datetime

class KaliRegistrationSchema(BaseModel):
    lab_id: str = Field(default="Kali-Lab-01")
    source_name: str = Field(default="Kali-Lab-01")
    source_type: str = Field(default="CONTROLLED_TEST_GENERATOR")
    target_endpoint_id: str = Field(default="local-host-01")
    authorized: bool = Field(default=True)
    operator: str = Field(default="ANALYST")

class KaliHeartbeatSchema(BaseModel):
    test_session_id: str
    timestamp: Optional[str] = None
    source_status: str = Field(default="ONLINE") # ONLINE, OFFLINE, BUSY
    current_scenario: Optional[str] = Field(default="IDLE")
    target_endpoint: str = Field(default="local-host-01")
    scenario_status: str = Field(default="IDLE") # IDLE, RUNNING, COMPLETED, STOPPED, FAILED

class KaliRunScenarioSchema(BaseModel):
    test_session_id: str
    scenario_id: str
    target_endpoint_id: str = Field(default="local-host-01")

class KaliTestEventPayload(BaseModel):
    event_id: str
    test_session_id: str
    scenario_id: str
    timestamp: str
    data_origin: str = Field(default="CONTROLLED_TEST")
    event_type: str
    details: Dict[str, Any]
