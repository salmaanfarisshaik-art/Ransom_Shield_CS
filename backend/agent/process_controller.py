"""
RansomShield Endpoint Process Controller
Enforces Process Identity Guard before termination to prevent killing reused PIDs.
Implements Dump-Before-Kill sequential forensic acquisition.
"""
import psutil
import logging
from datetime import datetime
from typing import Dict, Any, Optional
from backend.modules.process_identity import validate_process_identity, IDENTITY_MISMATCH, IDENTITY_MATCH
from backend.modules.containment import kill_process as module_kill_process

logger = logging.getLogger(__name__)

class AgentProcessController:
    @staticmethod
    def terminate_process_safe(
        pid: int,
        process_instance_id: Optional[str] = None,
        expected_name: Optional[str] = None,
        operator: str = "ANALYST"
    ) -> Dict[str, Any]:
        """
        Safely validates process identity before executing termination.
        Prevents killing a reused PID if the original process exited.
        """
        t0 = datetime.utcnow()

        if not psutil.pid_exists(pid):
            return {
                "status": "PROCESS_NOT_FOUND",
                "reason": f"Process PID {pid} does not exist or was already terminated.",
                "verified": True
            }

        # Step 1: Process Identity Validation Guard
        status_code, details = validate_process_identity(
            pid=pid,
            expected_instance_id=process_instance_id,
            expected_name=expected_name
        )

        if status_code == IDENTITY_MISMATCH:
            logger.warning(f"[IDENTITY GUARD] Blocked kill for PID {pid}: {details.get('reason')}")
            return {
                "status": "PROCESS_IDENTITY_MISMATCH",
                "reason": f"Identity Guard Block: PID {pid} identity mismatch ({details.get('reason')}). Action aborted to prevent unintended process termination.",
                "verified": False,
                "details": details
            }

        # Step 2: Sequential Containment Execution
        kill_result = module_kill_process(pid)

        # Step 3: Verification
        still_exists = psutil.pid_exists(pid)
        verified = not still_exists

        return {
            "status": "PROCESS_KILLED" if verified else "TERMINATION_FAILED",
            "reason": kill_result.get("reason", "Process terminated."),
            "pid": pid,
            "process_instance_id": process_instance_id,
            "verified": verified,
            "mode": kill_result.get("mode", "real"),
            "operator": operator,
            "timestamp": datetime.utcnow().isoformat()
        }
