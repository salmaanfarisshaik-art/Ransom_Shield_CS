"""
RansomShield Dump-Before-Kill Forensic Containment Service (Phase T & Phase U & Phase V & Phase 43)
Implements evidence-preserving sequential containment pipeline with configurable retention modes,
sub-second latency metrics, process identity validation, and network isolation.
"""
import os
import time
import psutil
import logging
from datetime import datetime
from sqlalchemy.orm import Session
from backend.models.entities import (
    MemoryImageRecord, ResponseActionRecord, AuditLogRecord
)
from backend.modules.memory_forensics import acquire_minidump
from backend.services.evidence_service import compute_file_sha256, EvidenceService
from backend.services.yara_service import YaraService
from backend.services.volatility_service import VolatilityService
from backend.services.incident_service import IncidentService
from backend.modules.containment import isolate_endpoint as module_isolate_endpoint

logger = logging.getLogger(__name__)

RETENTION_MODE = os.getenv("RETENTION_MODE", "RESEARCH") # TEMPORARY, FORENSIC, RESEARCH

class ContainmentService:
    @staticmethod
    def execute_dump_before_kill(
        db: Session,
        pid: int,
        endpoint_id: str = "local-host-01",
        process_instance_id: str = None,
        operator: str = "ANALYST",
        retention_mode: str = RETENTION_MODE
    ) -> dict:
        
        t0 = time.time()
        
        if not psutil.pid_exists(pid):
            return {
                "status": "PROCESS_NOT_FOUND",
                "reason": f"Process PID {pid} does not exist or was already terminated.",
                "verified": True,
                "latencies_ms": {"total_response": round((time.time() - t0) * 1000, 2)}
            }

        # Step 0: Process Identity PID-Reuse Guard Check
        from backend.modules.process_identity import validate_process_identity, IDENTITY_MISMATCH
        identity_status, identity_details = validate_process_identity(pid)
        if identity_status == IDENTITY_MISMATCH:
            return {
                "status": "IDENTITY_MISMATCH",
                "reason": f"PID reuse guard blocked containment action: {identity_details.get('reason')}",
                "verified": False,
                "latencies_ms": {"total_response": round((time.time() - t0) * 1000, 2)}
            }


        # Step 1: Memory Acquisition (MiniDump)
        dump_dir = os.path.join(os.path.dirname(__file__), "..", "data", "memory_dumps")
        os.makedirs(dump_dir, exist_ok=True)
        dump_filepath = os.path.join(dump_dir, f"proc_{pid}_{int(t0)}.dmp")

        t_dump_start = time.time()
        dump_success = acquire_minidump(pid, dump_filepath)
        t_dump_end = time.time()
        dump_latency_ms = round((t_dump_end - t_dump_start) * 1000, 2)

        dump_hash = "0" * 64
        file_size = 0
        if dump_success and os.path.exists(dump_filepath):
            dump_hash = compute_file_sha256(dump_filepath)
            file_size = os.path.getsize(dump_filepath)

        mem_record = MemoryImageRecord(
            endpoint_id=endpoint_id,
            pid=pid,
            process_instance_id=process_instance_id,
            creation_time=datetime.utcnow(),
            acquisition_time=datetime.utcnow(),
            dump_type="MiniDumpWithFullMemory",
            file_path=dump_filepath,
            file_size=file_size,
            sha256=dump_hash,
            collector="Win32_MiniDumpWriteDump",
            status="ACQUIRED" if dump_success else "FAILED",
            analysis_status="IN_PROGRESS",
            retention_policy=retention_mode
        )
        db.add(mem_record)
        db.commit()

        # Step 2: Forensic Analysis (YARA + Volatility)
        t_analysis_start = time.time()
        yara_result = {"status": "NO_MATCH", "match": False}
        if dump_success and os.path.exists(dump_filepath):
            yara_result = YaraService.scan_memory_dump(
                db=db,
                dump_filepath=dump_filepath,
                memory_image_id=mem_record.memory_image_id,
                process_instance_id=process_instance_id,
                endpoint_id=endpoint_id
            )
            # Optional Volatility analysis
            if VolatilityService.is_available():
                VolatilityService.analyze_memory_dump(
                    db=db,
                    memory_image_id=mem_record.memory_image_id,
                    dump_filepath=dump_filepath,
                    endpoint_id=endpoint_id,
                    process_instance_id=process_instance_id
                )

        t_analysis_end = time.time()
        analysis_latency_ms = round((t_analysis_end - t_analysis_start) * 1000, 2)

        # Step 3: Handle retention mode
        if retention_mode == "TEMPORARY" and os.path.exists(dump_filepath):
            try:
                os.remove(dump_filepath)
                mem_record.status = "DELETED"
                db.commit()
            except Exception as e:
                logger.error(f"Failed temporary dump deletion: {e}")

        # Step 4: Process Termination (psutil)
        t_containment_start = time.time()
        kill_reason = "Graceful termination succeeded."
        kill_status = "SUCCESS"

        try:
            proc = psutil.Process(pid)
            proc.terminate()
            try:
                proc.wait(timeout=3.0)
            except psutil.TimeoutExpired:
                proc.kill()
                kill_reason = "Force killed after 3s timeout."
        except psutil.NoSuchProcess:
            kill_reason = "Process exited before termination call."
        except psutil.AccessDenied:
            kill_status = "PERMISSION_REQUIRED"
            kill_reason = "Access Denied: Insufficient privileges."
        except Exception as e:
            kill_status = "FAILED"
            kill_reason = f"Unexpected error: {str(e)}"

        t_containment_end = time.time()
        containment_latency_ms = round((t_containment_end - t_containment_start) * 1000, 2)
        total_response_latency_ms = round((time.time() - t0) * 1000, 2)

        # Step 5: Verification (Never report success unless verified)
        is_alive = psutil.pid_exists(pid)
        verified_dead = not is_alive

        if kill_status == "SUCCESS" and is_alive:
            kill_status = "VERIFICATION_FAILED"
            kill_reason = "Process remains active after termination attempt."

        # Log Response Action
        resp_action = ResponseActionRecord(
            timestamp=datetime.utcnow(),
            endpoint_id=endpoint_id,
            action_type="PROCESS_KILL",
            process_instance_id=process_instance_id or f"{endpoint_id}:{pid}",
            trigger_reason=kill_reason,
            status=kill_status,
            mode="REAL",
            operator=operator,
            verification_details={
                "pid": pid,
                "verified_dead": verified_dead,
                "dump_sha256": dump_hash,
                "latencies_ms": {
                    "dump": dump_latency_ms,
                    "analysis": analysis_latency_ms,
                    "containment": containment_latency_ms,
                    "total_response": total_response_latency_ms
                }
            }
        )
        db.add(resp_action)
        db.commit()

        # Add to timeline
        IncidentService.add_timeline_event(
            db=db,
            endpoint_id=endpoint_id,
            event_type="PROCESS_CONTAINED",
            description=f"Sequential dump-before-kill executed on PID {pid}. Status: {kill_status}. Response time: {total_response_latency_ms}ms.",
            source_module="ContainmentService",
            raw_event_id=resp_action.id
        )

        return {
            "status": kill_status,
            "reason": kill_reason,
            "verified": verified_dead,
            "memory_dump": {
                "acquired": dump_success,
                "sha256": dump_hash,
                "retention_policy": retention_mode
            },
            "latencies_ms": {
                "dump": dump_latency_ms,
                "analysis": analysis_latency_ms,
                "containment": containment_latency_ms,
                "total_response": total_response_latency_ms
            }
        }

    @staticmethod
    def isolate_endpoint(
        db: Session,
        endpoint_id: str,
        simulated: bool = True,
        operator: str = "ANALYST"
    ) -> dict:
        
        res = module_isolate_endpoint(endpoint_id, simulated=simulated)
        
        resp_action = ResponseActionRecord(
            timestamp=datetime.utcnow(),
            endpoint_id=endpoint_id,
            action_type="NETWORK_ISOLATE",
            trigger_reason=res["reason"],
            status=res["status"].upper(),
            mode="SIMULATED" if simulated else "REAL",
            operator=operator,
            verification_details=res
        )
        db.add(resp_action)
        db.commit()

        IncidentService.add_timeline_event(
            db=db,
            endpoint_id=endpoint_id,
            event_type="NETWORK_ISOLATED",
            description=f"Endpoint network isolation enforced ({'Simulated' if simulated else 'Real Firewall Rule'}).",
            source_module="ContainmentService",
            raw_event_id=resp_action.id
        )

        return res
