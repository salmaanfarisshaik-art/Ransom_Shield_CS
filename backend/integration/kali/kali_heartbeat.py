"""
RansomShield Kali Heartbeat & Status Manager
Monitors heartbeat status for Kali Linux test nodes and manages ONLINE / OFFLINE state.
"""
import time
import logging
from datetime import datetime
from typing import Dict, Any
from sqlalchemy.orm import Session
from backend.models.entities import LabNode, LabSession
from backend.integration.kali.kali_test_controller import active_sessions

logger = logging.getLogger(__name__)

# Cache for latest heartbeats
node_heartbeats: Dict[str, Dict[str, Any]] = {}

class KaliHeartbeatManager:

    @staticmethod
    def process_heartbeat(
        db: Session,
        test_session_id: str,
        source_status: str = "ONLINE",
        current_scenario: str = "IDLE",
        target_endpoint: str = "local-host-01",
        scenario_status: str = "IDLE"
    ) -> Dict[str, Any]:
        """Processes a periodic heartbeat from a registered Kali test node."""
        
        now = datetime.utcnow()

        if test_session_id in active_sessions:
            active_sessions[test_session_id]["status"] = source_status
            active_sessions[test_session_id]["current_scenario"] = current_scenario
            active_sessions[test_session_id]["scenario_status"] = scenario_status
            active_sessions[test_session_id]["last_seen"] = now.isoformat()

        # Update database record
        sess_rec = db.query(LabSession).filter(LabSession.session_id == test_session_id).first()
        if sess_rec:
            sess_rec.current_scenario = current_scenario
            sess_rec.scenario_status = scenario_status
            node = db.query(LabNode).filter(LabNode.lab_id == sess_rec.lab_id).first()
            if node:
                node.last_seen = now
                node.status = source_status
            db.commit()

        hb_info = {
            "test_session_id": test_session_id,
            "status": source_status,
            "current_scenario": current_scenario,
            "scenario_status": scenario_status,
            "target_endpoint": target_endpoint,
            "last_seen": now.isoformat()
        }
        node_heartbeats[test_session_id] = hb_info
        return hb_info

    @staticmethod
    def get_node_status(test_session_id: str = None) -> Dict[str, Any]:
        """Returns the current online/offline status of the Kali test node."""
        if test_session_id and test_session_id in active_sessions:
            return active_sessions[test_session_id]
        if active_sessions:
            # Return first active session
            return list(active_sessions.values())[0]
        return {
            "status": "OFFLINE",
            "source_name": "Kali-Lab-01",
            "current_scenario": "IDLE",
            "scenario_status": "IDLE",
            "authorized": False
        }
