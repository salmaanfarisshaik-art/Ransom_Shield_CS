"""
RansomShield Kali Test Controller
Handles registration, test session authorization, and scenario dispatching for Kali Linux test generator.
STRICT SAFETY ENFORCEMENT: ONLY PREDEFINED SCENARIOS ALLOWED.
NO ARBITRARY COMMAND EXECUTION. NO REMOTE SHELL. NO SCRIPT UPLOADS.
"""
import uuid
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session
from backend.models.entities import LabNode, LabSession, AuditLogRecord
from backend.integration.kali.kali_config import (
    KALI_LAB_DEFAULT_ID, KALI_SOURCE_NAME, KALI_SOURCE_TYPE, KALI_SESSION_TTL_MINUTES
)
from backend.integration.kali.kali_test_scenarios import get_scenario, list_scenarios

logger = logging.getLogger(__name__)

# In-memory store for active lab node sessions
active_sessions: Dict[str, Dict[str, Any]] = {}

class KaliTestController:

    @staticmethod
    def register_lab_node(
        db: Session,
        lab_id: str = KALI_LAB_DEFAULT_ID,
        source_name: str = KALI_SOURCE_NAME,
        source_type: str = KALI_SOURCE_TYPE,
        target_endpoint_id: str = "local-host-01",
        authorized: bool = True,
        operator: str = "ANALYST",
        ip_address: str = "127.0.0.1"
    ) -> Dict[str, Any]:
        """Registers a Kali Lab test generator node and creates an authorized session."""
        
        test_session_id = f"LAB-SESSION-{uuid.uuid4().hex[:8].upper()}"
        now = datetime.utcnow()
        expires = now + timedelta(minutes=KALI_SESSION_TTL_MINUTES)

        # Database record update / creation
        node = db.query(LabNode).filter(LabNode.source_name == source_name).first()
        if not node:
            node = LabNode(
                lab_id=lab_id,
                source_name=source_name,
                source_type=source_type,
                target_endpoint_id=target_endpoint_id,
                authorized=authorized,
                ip_address=ip_address,
                last_seen=now,
                status="ONLINE"
            )
            db.add(node)
        else:
            node.authorized = authorized
            node.last_seen = now
            node.status = "ONLINE"
            node.ip_address = ip_address

        sess_rec = LabSession(
            session_id=test_session_id,
            lab_id=node.lab_id,
            source_name=source_name,
            target_endpoint_id=target_endpoint_id,
            current_scenario="IDLE",
            scenario_status="IDLE",
            started_at=now,
            expires_at=expires,
            operator=operator,
            status="ACTIVE"
        )
        db.add(sess_rec)

        audit = AuditLogRecord(
            actor=operator,
            role="ANALYST",
            action="KALI_LAB_NODE_REGISTERED",
            target=f"{source_name} ({test_session_id})",
            result="SUCCESS"
        )
        db.add(audit)
        db.commit()

        # Update in-memory session cache
        session_info = {
            "test_session_id": test_session_id,
            "lab_id": node.lab_id,
            "source_name": source_name,
            "source_type": source_type,
            "target_endpoint_id": target_endpoint_id,
            "authorized": authorized,
            "operator": operator,
            "status": "ONLINE",
            "current_scenario": "IDLE",
            "scenario_status": "IDLE",
            "created_at": now.isoformat(),
            "expires_at": expires.isoformat()
        }
        active_sessions[test_session_id] = session_info

        logger.info(f"Registered Kali Lab session {test_session_id} for {source_name}")
        return session_info

    @staticmethod
    def validate_session(test_session_id: str) -> bool:
        """Validates that a test session is active and authorized."""
        if test_session_id not in active_sessions:
            return False
        sess = active_sessions[test_session_id]
        if not sess.get("authorized", False):
            return False
        return True

    @staticmethod
    def run_safe_scenario(
        db: Session,
        test_session_id: str,
        scenario_id: str,
        target_endpoint_id: str = "local-host-01",
        operator: str = "ANALYST"
    ) -> Dict[str, Any]:
        """
        Validates authorization and dispatches ONLY a predefined safe scenario ID.
        Rejects any command strings, arbitrary code, or unauthorized payloads.
        """
        if not KaliTestController.validate_session(test_session_id):
            return {
                "status": "UNAUTHORIZED",
                "error": "Test session invalid or not authorized. Register Kali node first.",
                "scenario_id": scenario_id
            }

        scenario = get_scenario(scenario_id)
        if not scenario:
            return {
                "status": "INVALID_SCENARIO",
                "error": f"Scenario ID '{scenario_id}' is not in the predefined safe scenario registry.",
                "allowed_scenarios": list(get_scenario(s)["scenario_id"] for s in ["SCENARIO_1", "SCENARIO_2", "SCENARIO_3", "SCENARIO_4", "SCENARIO_5", "SCENARIO_6", "SCENARIO_7"])
            }

        # Update session status
        active_sessions[test_session_id]["current_scenario"] = scenario_id
        active_sessions[test_session_id]["scenario_status"] = "RUNNING"

        sess_rec = db.query(LabSession).filter(LabSession.session_id == test_session_id).first()
        if sess_rec:
            sess_rec.current_scenario = scenario_id
            sess_rec.scenario_status = "RUNNING"
            db.commit()

        logger.info(f"[KALI LAB] Dispatched scenario {scenario_id} ({scenario['scenario_name']}) for session {test_session_id}")

        return {
            "status": "DISPATCHED",
            "test_session_id": test_session_id,
            "scenario": scenario,
            "target_endpoint_id": target_endpoint_id,
            "dispatched_at": datetime.utcnow().isoformat(),
            "data_origin": "CONTROLLED_TEST"
        }

    @staticmethod
    def stop_scenario(db: Session, test_session_id: str) -> Dict[str, Any]:
        """Stops an active test scenario."""
        if test_session_id in active_sessions:
            active_sessions[test_session_id]["current_scenario"] = "IDLE"
            active_sessions[test_session_id]["scenario_status"] = "STOPPED"

        sess_rec = db.query(LabSession).filter(LabSession.session_id == test_session_id).first()
        if sess_rec:
            sess_rec.current_scenario = "IDLE"
            sess_rec.scenario_status = "STOPPED"
            db.commit()

        return {"status": "STOPPED", "test_session_id": test_session_id}
