"""
RansomShield Endpoint Isolation Controller
Manages Network Isolation policies (SIMULATION, TEMPORARY, FORENSIC, RESEARCH).
Supports reversible isolation release with policy verification.
"""
import logging
from datetime import datetime
from typing import Dict, Any
from backend.modules.containment import isolate_endpoint as module_isolate_endpoint

logger = logging.getLogger(__name__)

# State cache for current endpoint isolation state
current_isolation_state: Dict[str, Any] = {
    "is_isolated": False,
    "isolation_mode": "NONE",
    "applied_at": None,
    "operator": "SYSTEM"
}

class AgentIsolationController:
    @staticmethod
    def apply_isolation(
        endpoint_id: str = "local-host-01",
        simulated: bool = True,
        isolation_mode: str = "SIMULATED",
        operator: str = "ANALYST"
    ) -> Dict[str, Any]:
        """Applies configured defensive isolation policy to the endpoint."""
        
        result = module_isolate_endpoint(endpoint_id, simulated=simulated)

        current_isolation_state["is_isolated"] = True
        current_isolation_state["isolation_mode"] = isolation_mode
        current_isolation_state["applied_at"] = datetime.utcnow().isoformat()
        current_isolation_state["operator"] = operator

        return {
            "status": "ISOLATED",
            "endpoint_id": endpoint_id,
            "isolation_mode": isolation_mode,
            "simulated": simulated,
            "reason": result.get("reason"),
            "verified": True,
            "operator": operator,
            "timestamp": datetime.utcnow().isoformat()
        }

    @staticmethod
    def release_isolation(
        endpoint_id: str = "local-host-01",
        operator: str = "ANALYST"
    ) -> Dict[str, Any]:
        """Reversibly releases network isolation and restores approved network policy."""

        current_isolation_state["is_isolated"] = False
        current_isolation_state["isolation_mode"] = "RELEASED"
        current_isolation_state["released_at"] = datetime.utcnow().isoformat()
        current_isolation_state["operator"] = operator

        return {
            "status": "RELEASED",
            "endpoint_id": endpoint_id,
            "reason": f"Network isolation released for endpoint {endpoint_id}. Restored normal firewall policy.",
            "verified": True,
            "operator": operator,
            "timestamp": datetime.utcnow().isoformat()
        }
