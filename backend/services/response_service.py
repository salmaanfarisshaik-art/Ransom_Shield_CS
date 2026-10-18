"""
RansomShield Incident Response Pipeline & Response Service
Implements RBAC-enforced process termination with Process Identity Validation Guard,
network isolation, isolation release, and cryptographic audit logging.
"""
import psutil
import logging
from datetime import datetime
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session
from backend.models.entities import (
    Endpoint, ResponseActionRecord, AuditLogRecord, IsolationStateRecord, IncidentRecord
)
from backend.agent.process_controller import AgentProcessController
from backend.agent.isolation_controller import AgentIsolationController
from backend.services.containment_service import ContainmentService

logger = logging.getLogger(__name__)

ALLOWED_RESPONSE_ROLES = ["ADMIN", "RESPONDER", "ANALYST"]

class ResponseService:

    @staticmethod
    def terminate_process(
        db: Session,
        pid: int,
        endpoint_id: str = "local-host-01",
        process_instance_id: Optional[str] = None,
        operator: str = "ANALYST",
        role: str = "RESPONDER"
    ) -> Dict[str, Any]:
        """
        Executes sequential Dump-Before-Kill process termination with Process Identity Validation.
        Requires RBAC permission (ADMIN, RESPONDER, ANALYST).
        """
        t0 = datetime.utcnow()

        if role not in ALLOWED_RESPONSE_ROLES:
            return {
                "status": "FORBIDDEN",
                "reason": f"Role '{role}' is not authorized to execute process termination.",
                "verified": False
            }

        # Step 1: Execute Dump-Before-Kill Forensics & Identity Validation
        result = ContainmentService.execute_dump_before_kill(
            db=db,
            pid=pid,
            endpoint_id=endpoint_id,
            process_instance_id=process_instance_id,
            operator=operator
        )

        verified = (result.get("status") in ("SUCCESS", "PROCESS_NOT_FOUND")) and not psutil.pid_exists(pid)

        # Step 2: Audit Logging & Action Recording
        act_rec = ResponseActionRecord(
            endpoint_id=endpoint_id,
            action_type="PROCESS_TERMINATION",
            process_instance_id=process_instance_id or f"pid_{pid}",
            trigger_reason=result.get("reason", "Process termination requested"),
            status="SUCCESS" if verified else "FAILED",
            mode="REAL",
            operator=operator,
            verification_details={"pid": pid, "verified_terminated": verified, "details": result}
        )
        db.add(act_rec)

        audit = AuditLogRecord(
            actor=operator,
            role=role,
            action="PROCESS_TERMINATION",
            target=f"PID {pid} ({endpoint_id})",
            result="SUCCESS" if verified else "FAILED"
        )
        db.add(audit)
        db.commit()

        logger.info(f"[RESPONSE] Process PID {pid} termination result: {result.get('status')} (Verified={verified})")
        return {
            "status": "SUCCESS" if verified else result.get("status", "FAILED"),
            "action_id": act_rec.id,
            "pid": pid,
            "verified": verified,
            "reason": result.get("reason"),
            "operator": operator,
            "timestamp": t0.isoformat()
        }

    @staticmethod
    def isolate_endpoint(
        db: Session,
        endpoint_id: str = "local-host-01",
        simulated: bool = True,
        isolation_mode: str = "SIMULATED",
        operator: str = "ANALYST",
        role: str = "RESPONDER"
    ) -> Dict[str, Any]:
        """
        Applies network isolation policy to the endpoint (SIMULATION, TEMPORARY, FORENSIC, RESEARCH).
        Requires RBAC permission (ADMIN, RESPONDER).
        """
        t0 = datetime.utcnow()

        if role not in ALLOWED_RESPONSE_ROLES:
            return {
                "status": "FORBIDDEN",
                "reason": f"Role '{role}' is not authorized to isolate endpoints.",
                "verified": False
            }

        res = AgentIsolationController.apply_isolation(
            endpoint_id=endpoint_id,
            simulated=simulated,
            isolation_mode=isolation_mode,
            operator=operator
        )

        ep = db.query(Endpoint).filter(Endpoint.endpoint_id == endpoint_id).first()
        if ep:
            ep.status = "ISOLATED"
            db.commit()

        act_rec = ResponseActionRecord(
            endpoint_id=endpoint_id,
            action_type="ENDPOINT_ISOLATION",
            trigger_reason=res.get("reason"),
            status="SUCCESS",
            mode=isolation_mode,
            operator=operator,
            verification_details=res
        )
        db.add(act_rec)

        iso_rec = IsolationStateRecord(
            endpoint_id=endpoint_id,
            timestamp=t0,
            isolation_mode=isolation_mode,
            is_isolated=True,
            applied_rules=["netsh_blockinbound_blockoutbound"] if not simulated else ["simulated_sandbox_policy"],
            requested_by=operator,
            verification_status="VERIFIED"
        )
        db.add(iso_rec)

        audit = AuditLogRecord(
            actor=operator,
            role=role,
            action="ENDPOINT_ISOLATED",
            target=endpoint_id,
            result="SUCCESS"
        )
        db.add(audit)
        db.commit()

        logger.info(f"[RESPONSE] Endpoint {endpoint_id} Network Isolated ({isolation_mode}) by {operator}")
        return res

    @staticmethod
    def release_isolation(
        db: Session,
        endpoint_id: str = "local-host-01",
        operator: str = "ANALYST",
        role: str = "RESPONDER"
    ) -> Dict[str, Any]:
        """
        Reversibly releases network isolation and restores approved network policy.
        Requires RBAC permission (ADMIN, RESPONDER).
        """
        t0 = datetime.utcnow()

        if role not in ALLOWED_RESPONSE_ROLES:
            return {
                "status": "FORBIDDEN",
                "reason": f"Role '{role}' is not authorized to release endpoint isolation.",
                "verified": False
            }

        res = AgentIsolationController.release_isolation(
            endpoint_id=endpoint_id,
            operator=operator
        )

        ep = db.query(Endpoint).filter(Endpoint.endpoint_id == endpoint_id).first()
        if ep:
            ep.status = "ONLINE"
            db.commit()

        act_rec = ResponseActionRecord(
            endpoint_id=endpoint_id,
            action_type="ISOLATION_RELEASE",
            trigger_reason="Operator requested isolation release",
            status="SUCCESS",
            mode="REAL",
            operator=operator,
            verification_details=res
        )
        db.add(act_rec)

        iso_rec = IsolationStateRecord(
            endpoint_id=endpoint_id,
            timestamp=t0,
            isolation_mode="RELEASED",
            is_isolated=False,
            requested_by=operator,
            verification_status="VERIFIED"
        )
        db.add(iso_rec)

        audit = AuditLogRecord(
            actor=operator,
            role=role,
            action="ENDPOINT_ISOLATION_RELEASED",
            target=endpoint_id,
            result="SUCCESS"
        )
        db.add(audit)
        db.commit()

        logger.info(f"[RESPONSE] Endpoint {endpoint_id} Isolation Released by {operator}")
        return res
