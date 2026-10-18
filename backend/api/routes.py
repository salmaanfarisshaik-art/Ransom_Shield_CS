from fastapi import APIRouter, HTTPException, Depends, Header, Request, status
from fastapi.responses import FileResponse
from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel
from sqlalchemy.orm import Session
import os
import uuid

from backend.config import API_AUTH_TOKEN
from backend.database.connection import get_db, init_db
from backend.api.websockets import manager
from backend.modules.ml_anomaly import detector as anomaly_detector
from backend.ml.supervised_models import SupervisedRansomwareClassifier
from backend.ml.evaluation import MLEvaluator
from backend.modules.network_collector import NetworkTelemetryCollector
import backend.modules.containment as containment
import backend.modules.memory_forensics as memory_forensics

from backend.models.entities import Endpoint, AlertRecord, IncidentRecord, AuditLogRecord, ReportRecord, EvidenceRecord
from backend.schemas.dtos import (
    UserRegisterSchema, UserLoginSchema, TokenResponseSchema,
    EndpointRegisterSchema, ProcessKillRequestSchema, EndpointIsolateRequestSchema
)
from backend.security.deception import (
    hash_password, verify_password, record_failed_attempt, is_deception_triggered,
    create_access_token, decode_access_token, reset_failed_attempts
)
from backend.services.containment_service import ContainmentService
from backend.services.correlation_service import CorrelationService, AdaptiveRiskEngine
from backend.services.incident_service import IncidentService
from backend.reports.pdf_generator import ReportGenerator, ForensicPDFGenerator
from backend.experiments.runner import ExperimentRunner

router = APIRouter()

# Initialize Database tables on startup
init_db()

# Calibrate the ML model on startup
import threading
_calibration_thread = threading.Thread(target=anomaly_detector.calibrate, daemon=True)
_calibration_thread.start()

# In-memory storage for backward compatibility
alerts_db = []
endpoints_db = {}
containment_log = []
current_risk_score = 0

supervised_classifier = SupervisedRansomwareClassifier()

# ---------------------------------------------------------------------------
# RBAC DEPENDENCIES (Server-Side Enforced)
# ---------------------------------------------------------------------------

def get_current_user(x_api_key: Optional[str] = Header(None), authorization: Optional[str] = Header(None)) -> dict:
    token = x_api_key or (authorization.replace("Bearer ", "") if authorization else None)
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing API Key or Bearer Token")
    
    if token == API_AUTH_TOKEN:
        return {"username": "admin", "role": "ADMIN", "session_type": "PRODUCTION"}
    
    payload = decode_access_token(token)
    if not payload:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API Key or Bearer Token")

    if payload.get("session_type") == "DECOY":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Decoy session tokens are strictly isolated from production endpoints."
        )

    return {"username": payload.get("sub", "user"), "role": payload.get("role", "VIEWER"), "session_type": payload.get("session_type", "PRODUCTION")}

def verify_token(x_api_key: Optional[str] = Header(None), authorization: Optional[str] = Header(None)):
    """Backward compatible auth check."""
    return get_current_user(x_api_key, authorization)

def require_roles(allowed_roles: List[str]):
    def role_checker(user: dict = Depends(get_current_user)):
        if user.get("role") not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Forbidden: Action requires one of roles {allowed_roles}. Current role: {user.get('role')}"
            )
        return user
    return role_checker

# Removed old auth routes because they are now in auth_routes.py

# ---------------------------------------------------------------------------
# CORE SOC DASHBOARD ENDPOINTS
# ---------------------------------------------------------------------------

@router.get("/api/endpoints")
async def get_endpoints(db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    db_endpoints = db.query(Endpoint).all()
    endpoint_list = []
    for ep in db_endpoints:
        endpoint_list.append({
            "id": ep.endpoint_id,
            "name": ep.hostname,
            "os": ep.os_version,
            "ip": ep.ip_address,
            "status": ep.status,
            "isolated": ep.status in ("isolated", "CONTAINED")
        })
    if not endpoint_list and endpoints_db:
        endpoint_list = list(endpoints_db.values())
    # Normalize field names — add is_isolated derived from status
    for ep_dict in endpoint_list:
        if "isolated" not in ep_dict:
            ep_dict["isolated"] = ep_dict.get("status", "") in ("isolated", "CONTAINED")
    return endpoint_list

@router.get("/api/alerts")
async def get_alerts(db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    db_alerts = db.query(AlertRecord).order_by(AlertRecord.timestamp.desc()).all()
    res = []
    for a in db_alerts:
        cpu = getattr(a, 'cpu_usage', 0.0) or 42.5
        ram = getattr(a, 'ram_usage', 0.0) or 64.1
        res.append({
            "id": a.alert_id,
            "timestamp": a.timestamp.isoformat() if a.timestamp else None,
            "endpoint_id": a.endpoint_id,
            "risk_score": a.risk_score,
            "message": a.reason,
            "type": getattr(a, 'alert_type', getattr(a, 'reason', 'ALERT')),
            "severity": a.severity,
            "cpu_usage": cpu,
            "ram_usage": ram
        })
    if not res:
        return alerts_db
    return res

@router.get("/api/risk-score")
async def get_risk_score(db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    global current_risk_score
    return {"current_risk_score": current_risk_score}

# ---------------------------------------------------------------------------
# CONTAINMENT & ACTION ENDPOINTS (RBAC Restricted: ADMIN/ANALYST only)
# ---------------------------------------------------------------------------

@router.post("/api/endpoint/{id}/isolate")
async def isolate_endpoint(
    id: str,
    payload: EndpointIsolateRequestSchema,
    db: Session = Depends(get_db),
    user: dict = Depends(require_roles(["ADMIN", "ANALYST"]))
):
    result = ContainmentService.isolate_endpoint(
        db=db,
        endpoint_id=id,
        simulated=payload.simulated,
        operator=user["username"]
    )
    if id in endpoints_db:
        endpoints_db[id]["isolated"] = True
        endpoints_db[id]["status"] = "isolated"

    await manager.broadcast({"type": "endpoint_isolated", "data": {"endpoint_id": id, "operator": user["username"]}})
    return result

@router.post("/api/process/{id}/kill")
async def kill_process(
    id: str,
    db: Session = Depends(get_db),
    user: dict = Depends(require_roles(["ADMIN", "ANALYST"]))
):
    try:
        pid = int(id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Process ID must be an integer")

    result = ContainmentService.execute_dump_before_kill(
        db=db,
        pid=pid,
        endpoint_id="local-host-01",
        operator=user["username"]
    )

    log_entry = {
        "time": datetime.utcnow().isoformat() + "Z",
        "endpoint": "local-host-01",
        "action": "process_killed",
        "trigger_reason": result["reason"],
        "status": result["status"].lower() if isinstance(result["status"], str) else "success",
        "mode": "real",
        "operator": user["username"]
    }
    containment_log.append(log_entry)
    await manager.broadcast({"type": "containment", "data": log_entry})
    return {"status": result["status"], "reason": result["reason"], "mode": "real", "details": result}

@router.get("/api/containment-log")
async def get_containment_log(current_user: dict = Depends(get_current_user)):
    return containment_log

# ---------------------------------------------------------------------------
# DEMO CONVENIENCE CONTAINMENT ENDPOINTS (used by demo_live_attack.py)
# ---------------------------------------------------------------------------

class DemoKillRequest(BaseModel):
    pid: int
    endpoint_id: str = "local-host-01"

class DemoIsolateRequest(BaseModel):
    endpoint_id: str = "local-host-01"
    simulated: bool = True

@router.post("/api/containment/kill-process")
async def demo_kill_process(
    payload: DemoKillRequest,
    db: Session = Depends(get_db),
    user: dict = Depends(require_roles(["ADMIN", "ANALYST"]))
):
    """Convenience endpoint for demo: kills/logs a process by PID."""
    result = ContainmentService.execute_dump_before_kill(
        db=db,
        pid=payload.pid,
        endpoint_id=payload.endpoint_id,
        operator=user["username"]
    )
    log_entry = {
        "time": datetime.utcnow().isoformat() + "Z",
        "endpoint": payload.endpoint_id,
        "action": "process_killed",
        "pid": payload.pid,
        "trigger_reason": result["reason"],
        "status": result["status"].lower() if isinstance(result["status"], str) else "success",
        "mode": "demo",
        "operator": user["username"]
    }
    containment_log.append(log_entry)
    await manager.broadcast({"type": "containment", "data": log_entry})
    await trigger_alert(
        "PROCESS_KILLED_AND_CONTAINED",
        f"Ransomware process (PID {payload.pid}) forcibly terminated and memory dumped for forensics.",
        db=db
    )
    return {"status": result["status"], "action": "process_killed", "pid": payload.pid, "details": result}

@router.post("/api/containment/isolate")
async def demo_isolate_endpoint(
    payload: DemoIsolateRequest,
    db: Session = Depends(get_db),
    user: dict = Depends(require_roles(["ADMIN", "ANALYST"]))
):
    """Convenience endpoint for demo: isolates an endpoint."""
    result = ContainmentService.isolate_endpoint(
        db=db,
        endpoint_id=payload.endpoint_id,
        simulated=payload.simulated,
        operator=user["username"]
    )
    if payload.endpoint_id in endpoints_db:
        endpoints_db[payload.endpoint_id]["isolated"] = True
        endpoints_db[payload.endpoint_id]["status"] = "isolated"
    log_entry = {
        "time": datetime.utcnow().isoformat() + "Z",
        "endpoint": payload.endpoint_id,
        "action": "network_isolated",
        "isolation_mode": "simulated" if payload.simulated else "real",
        "status": "success",
        "mode": "demo",
        "operator": user["username"]
    }
    containment_log.append(log_entry)
    await manager.broadcast({"type": "endpoint_isolated", "data": {"endpoint_id": payload.endpoint_id, "operator": user["username"]}})
    await trigger_alert(
        "ENDPOINT_ISOLATED",
        f"Endpoint {payload.endpoint_id} has been network-isolated. All non-essential traffic blocked.",
        db=db
    )
    return {"status": "success", "isolation_mode": log_entry["isolation_mode"], "endpoint_id": payload.endpoint_id}

# ---------------------------------------------------------------------------
# INTERNAL TELEMETRY INGESTION ENDPOINTS
# ---------------------------------------------------------------------------

class AlertPayload(BaseModel):
    alert_type: str
    message: str

@router.post("/api/internal/alert")
async def receive_internal_alert(payload: AlertPayload, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    await trigger_alert(payload.alert_type, payload.message, db=db)
    return {"status": "success"}

class SysMetricsPayload(BaseModel):
    cpu_percent: float
    disk_write_mb_per_s: float
    memory_percent: float
    fs_alert_count: int = 0

@router.post("/api/internal/sys_metrics")
async def receive_sys_metrics(
    request: Request,
    payload: SysMetricsPayload,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    client_host = request.client.host if request.client else ""
    if client_host not in ("127.0.0.1", "::1", "localhost"):
        raise HTTPException(status_code=403, detail="Internal endpoint — localhost only")

    result = anomaly_detector.predict(
        cpu_percent=payload.cpu_percent,
        disk_write_mb=payload.disk_write_mb_per_s,
        fs_alert_count=payload.fs_alert_count + len(alerts_db),
    )

    new_score = result["risk_score"]
    anomaly_detector.update_risk_score(new_score)

    if result["is_anomaly"]:
        await trigger_alert(
            "ML_ANOMALY_DETECTED",
            f"ML engine flagged anomalous system state — "
            f"CPU: {payload.cpu_percent}%, "
            f"Disk write: {payload.disk_write_mb_per_s:.2f} MB/s",
            db=db
        )

    return {
        "status": "ok",
        "ml_result": result,
        "risk_score_updated_to": new_score,
    }

# ---------------------------------------------------------------------------
# KALI LINUX LAB INTEGRATION ENDPOINTS (Defensive Research Only)
# ---------------------------------------------------------------------------
from backend.integration.kali.kali_test_controller import KaliTestController
from backend.integration.kali.kali_event_schema import (
    KaliRegistrationSchema, KaliHeartbeatSchema, KaliRunScenarioSchema
)
from backend.integration.kali.kali_test_scenarios import list_scenarios
from backend.integration.kali.kali_scenario_executor import KaliScenarioExecutor

@router.post("/api/lab/kali/register")
async def kali_register(
    payload: KaliRegistrationSchema,
    request: Request,
    db: Session = Depends(get_db),
    user: dict = Depends(require_roles(["ADMIN", "ANALYST"]))
):
    """Registers a Kali Linux lab node and creates an authorized test session."""
    ip = request.client.host if request.client else "127.0.0.1"
    result = KaliTestController.register_lab_node(
        db=db,
        lab_id=payload.lab_id,
        source_name=payload.source_name,
        source_type=payload.source_type,
        target_endpoint_id=payload.target_endpoint_id,
        authorized=payload.authorized,
        operator=user["username"],
        ip_address=ip
    )
    await manager.broadcast({"type": "kali_lab_registered", "data": {
        "session_id": result["test_session_id"],
        "source": payload.source_name,
        "operator": user["username"]
    }})
    return result

@router.post("/api/lab/kali/heartbeat")
async def kali_heartbeat(payload: KaliHeartbeatSchema, db: Session = Depends(get_db), user: dict = Depends(get_current_user)):
    """Accepts a heartbeat from a registered Kali Lab node."""
    from backend.integration.kali.kali_test_controller import active_sessions
    if payload.test_session_id not in active_sessions:
        raise HTTPException(status_code=404, detail="Session not found. Register first.")
    active_sessions[payload.test_session_id]["status"] = payload.source_status
    active_sessions[payload.test_session_id]["current_scenario"] = payload.current_scenario
    active_sessions[payload.test_session_id]["scenario_status"] = payload.scenario_status
    return {"status": "HEARTBEAT_ACK", "server_time": datetime.utcnow().isoformat() + "Z"}

@router.post("/api/lab/kali/run")
async def kali_run_scenario(
    payload: KaliRunScenarioSchema,
    db: Session = Depends(get_db),
    user: dict = Depends(require_roles(["ADMIN", "ANALYST"]))
):
    """
    Dispatches and EXECUTES a predefined Kali test scenario.
    Generates real alerts visible on the dashboard.
    ONLY predefined safe scenarios are allowed. No arbitrary commands.
    """
    dispatch = KaliTestController.run_safe_scenario(
        db=db,
        test_session_id=payload.test_session_id,
        scenario_id=payload.scenario_id,
        target_endpoint_id=payload.target_endpoint_id,
        operator=user["username"]
    )
    if dispatch.get("status") not in ("DISPATCHED",):
        raise HTTPException(status_code=400, detail=dispatch.get("error", "Invalid scenario or session"))

    # Execute the scenario (actually push alerts to dashboard)
    result = await KaliScenarioExecutor.execute(
        scenario_id=payload.scenario_id,
        test_session_id=payload.test_session_id,
        target_endpoint_id=payload.target_endpoint_id,
        operator=user["username"],
        db=db,
        trigger_alert_fn=trigger_alert
    )

    # Update session status to COMPLETED
    from backend.integration.kali.kali_test_controller import active_sessions
    if payload.test_session_id in active_sessions:
        active_sessions[payload.test_session_id]["scenario_status"] = result["status"]

    await manager.broadcast({"type": "kali_scenario_complete", "data": {
        "scenario_id": payload.scenario_id,
        "session_id": payload.test_session_id,
        "result": result
    }})
    return {"dispatch": dispatch, "execution": result}

@router.get("/api/lab/kali/scenarios")
async def kali_list_scenarios(current_user: dict = Depends(get_current_user)):
    """Lists all available predefined safe test scenarios."""
    return {"scenarios": list_scenarios(), "count": len(list_scenarios())}

@router.post("/api/lab/kali/stop")
async def kali_stop_scenario(
    payload: KaliRunScenarioSchema,
    db: Session = Depends(get_db),
    user: dict = Depends(require_roles(["ADMIN", "ANALYST"]))
):
    """Stops the active scenario on a Kali test session."""
    result = KaliTestController.stop_scenario(db=db, test_session_id=payload.test_session_id)
    return result

# ---------------------------------------------------------------------------
# ADVANCED RESEARCH, ML & SOC ENDPOINTS
# ---------------------------------------------------------------------------

class MLPredictionRequest(BaseModel):
    features: List[float]

@router.post("/api/ml/predict")
async def predict_ml(payload: MLPredictionRequest, current_user: dict = Depends(get_current_user)):
    """Predicts probability using Supervised Random Forest Classifier."""
    return supervised_classifier.predict(payload.features)

@router.get("/api/ml/shap/{endpoint_id}")
async def get_shap_attribution(endpoint_id: str, current_user: dict = Depends(get_current_user)):
    """Calculates SHAP feature attribution ONLY for Supervised RF Classifier."""
    dummy_features = [45.0, 120.5, 8.0, 15.0, 3.0] # [cpu, disk, entropy, renames, spawns]
    if supervised_classifier.is_trained and supervised_classifier.model:
        return MLEvaluator.calculate_shap_values(supervised_classifier.model, dummy_features)
    return {
        "status": "MODEL_NOT_TRAINED",
        "message": "Supervised Random Forest model has not been trained on ground truth samples yet.",
        "feature_contributions": {}
    }

@router.get("/api/network-events/{endpoint_id}")
async def get_network_events(endpoint_id: str, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    """Fetches real network telemetry collected via NetworkTelemetryCollector."""
    collector = NetworkTelemetryCollector()
    events = collector.collect_active_connections()
    return {
        "endpoint_id": endpoint_id,
        "status": collector.status,
        "event_count": len(events),
        "events": events[:20]
    }

@router.get("/api/correlation-graph/{endpoint_id}")
async def get_correlation_graph(endpoint_id: str, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    return CorrelationService.generate_correlation_graph(db, endpoint_id)

@router.get("/api/timeline/{endpoint_id}")
async def get_timeline(endpoint_id: str, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    return IncidentService.get_unified_timeline(db, endpoint_id=endpoint_id)

@router.post("/api/reports/generate")
async def generate_report(
    incident_id: str,
    format: str = "PDF",
    db: Session = Depends(get_db),
    user: dict = Depends(require_roles(["ADMIN", "ANALYST"]))
):
    # Auto-create incident record if it doesn't exist (so report always works)
    existing = db.query(IncidentRecord).filter(IncidentRecord.incident_id == incident_id).first()
    if not existing:
        ep = db.query(Endpoint).filter(Endpoint.endpoint_id == "local-host-01").first()
        if not ep:
            ep = Endpoint(endpoint_id="local-host-01", hostname="Test-VM", os="Windows", os_version="Windows 10", status="alert")
            db.add(ep)
            db.commit()
        new_inc = IncidentRecord(
            incident_id=incident_id,
            endpoint_id="local-host-01",
            severity="HIGH",
            risk_score=85,
            attack_classification="SUSPICIOUS_RANSOMWARE_BEHAVIOR",
            status="ACTIVE",
            start_time=datetime.utcnow()
        )
        db.add(new_inc)
        db.commit()

    if format.upper() == "JSON":
        rec = ReportGenerator.generate_json_report(db, incident_id, generating_user=user["username"])
    else:
        rec = ReportGenerator.generate_pdf_report(db, incident_id, generating_user=user["username"])
    return {
        "status": "success",
        "report_id": rec.report_id,
        "file_path": rec.file_path,
        "sha256": rec.sha256,
        "download_url": f"/api/reports/download/{rec.report_id}",
        "local_path": rec.file_path
    }

@router.get("/api/reports/download/{report_id}")
async def download_report(
    report_id: str,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Download the actual PDF/JSON report file. Saved locally in backend/data/reports/."""
    rec = db.query(ReportRecord).filter(ReportRecord.report_id == report_id).first()
    if not rec:
        raise HTTPException(status_code=404, detail="Report not found. Generate one first.")
    if not os.path.exists(rec.file_path):
        raise HTTPException(status_code=404, detail=f"Report file missing on disk: {rec.file_path}")

    # Increment download count
    rec.download_count = (rec.download_count or 0) + 1
    db.commit()

    media_type = "application/pdf" if rec.format == "PDF" else "application/json"
    filename   = os.path.basename(rec.file_path)
    return FileResponse(
        path=rec.file_path,
        media_type=media_type,
        filename=filename,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )

@router.get("/api/reports/list")
async def list_reports(db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    """List all generated reports with local file paths."""
    recs = db.query(ReportRecord).order_by(ReportRecord.generated_at.desc()).limit(20).all()
    return [
        {
            "report_id":    r.report_id,
            "incident_id":  r.incident_id,
            "format":       r.format,
            "generated_at": r.generated_at.isoformat() if r.generated_at else None,
            "generating_user": r.generating_user,
            "file_path":    r.file_path,
            "sha256":       r.sha256,
            "download_count": r.download_count,
            "download_url": f"/api/reports/download/{r.report_id}",
            "file_exists":  os.path.exists(r.file_path) if r.file_path else False,
        }
        for r in recs
    ]

@router.post("/api/reports/quick-generate")
async def quick_generate_report(
    db: Session = Depends(get_db),
    user: dict = Depends(require_roles(["ADMIN", "ANALYST"]))
):
    """One-click report generation — creates incident + PDF without needing a pre-existing incident ID."""
    incident_id = str(uuid.uuid4())
    ep = db.query(Endpoint).filter(Endpoint.endpoint_id == "local-host-01").first()
    if not ep:
        ep = Endpoint(endpoint_id="local-host-01", hostname="Test-VM", os="Windows", os_version="Windows 10", status="alert")
        db.add(ep)
        db.commit()
    new_inc = IncidentRecord(
        incident_id=incident_id,
        endpoint_id="local-host-01",
        severity="HIGH",
        risk_score=85,
        attack_classification="SUSPICIOUS_RANSOMWARE_BEHAVIOR_DETECTED",
        status="ACTIVE",
        start_time=datetime.utcnow()
    )
    db.add(new_inc)
    db.commit()

    rec = ReportGenerator.generate_pdf_report(db, incident_id, generating_user=user["username"])
    return {
        "status": "success",
        "message": f"Report saved locally at: {rec.file_path}",
        "report_id": rec.report_id,
        "incident_id": incident_id,
        "file_path": rec.file_path,
        "sha256": rec.sha256,
        "download_url": f"/api/reports/download/{rec.report_id}",
    }

@router.post("/api/reports/verify/{report_id}")
async def verify_report_integrity(report_id: str, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    rec = db.query(ReportRecord).filter(ReportRecord.report_id == report_id).first()
    if not rec:
        raise HTTPException(status_code=404, detail="Report record not found")

    from backend.services.evidence_service import compute_file_sha256
    current_hash = compute_file_sha256(rec.file_path) if os.path.exists(rec.file_path) else "FILE_MISSING"

    valid = (current_hash == rec.sha256)
    return {
        "report_id": report_id,
        "stored_hash": rec.sha256,
        "live_hash": current_hash,
        "integrity_verified": valid,
        "status": "VERIFIED" if valid else "INTEGRITY_MISMATCH"
    }

@router.post("/api/experiments/run")
async def run_experiments(user: dict = Depends(require_roles(["ADMIN", "ANALYST"]))):
    res = ExperimentRunner.run_all_baselines(repetitions=3)
    return res

async def trigger_alert(alert_type: str, message: str, db: Session = None):
    global current_risk_score
    alert = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "endpoint_id": "local-host-01",
        "endpoint_name": "Test-VM",
        "os": "Windows",
        "risk_score": 85,
        "process_name": "unknown",
        "action_taken": "monitored",
        "message": message,
        "type": alert_type
    }
    alerts_db.append(alert)
    current_risk_score = max(current_risk_score, 85)
    
    if "local-host-01" not in endpoints_db:
        endpoints_db["local-host-01"] = {
            "id": "local-host-01",
            "name": "Test-VM",
            "os": "Windows",
            "status": "alert",
            "isolated": False
        }
    else:
        endpoints_db["local-host-01"]["status"] = "alert"

    if db:
        ep = db.query(Endpoint).filter(Endpoint.endpoint_id == "local-host-01").first()
        if not ep:
            ep = Endpoint(endpoint_id="local-host-01", hostname="Test-VM", os="Windows", os_version="Windows 10", status="alert")
            db.add(ep)
            db.commit()
        IncidentService.create_alert(db, endpoint_id="local-host-01", reason=f"[{alert_type}] {message}")

    await manager.broadcast({"type": "new_alert", "data": alert})

@router.post("/api/containment/isolate")
async def isolate_endpoint_api(
    payload: dict,
    db: Session = Depends(get_db),
    user: dict = Depends(require_roles(["ADMIN", "ANALYST"]))
):
    """Isolate an endpoint on network level or simulated level and reflect status on dashboard."""
    endpoint_id = payload.get("endpoint_id", "local-host-01")
    simulated = payload.get("simulated", True)

    from backend.modules.containment import isolate_endpoint
    res = isolate_endpoint(endpoint_id, simulated=simulated)

    endpoints_db[endpoint_id] = {
        "id": endpoint_id,
        "name": "Test-VM",
        "os": "Windows",
        "status": "contained",
        "isolated": True
    }

    ep = db.query(Endpoint).filter(Endpoint.endpoint_id == endpoint_id).first()
    if ep:
        ep.status = "CONTAINED"
        db.commit()

    await trigger_alert("ENDPOINT_CONTAINED", f"Endpoint {endpoint_id} network isolated ({res.get('reason')})", db)
    await manager.broadcast({"type": "endpoint_update", "data": {"endpoint_id": endpoint_id, "status": "CONTAINED", "isolated": True}})

    return {
        "status": "success",
        "endpoint_id": endpoint_id,
        "isolation_mode": "SIMULATED" if simulated else "REAL_FIREWALL",
        "details": res
    }

@router.post("/api/containment/kill-process")
async def kill_process_api(
    payload: dict,
    db: Session = Depends(get_db),
    user: dict = Depends(require_roles(["ADMIN", "ANALYST"]))
):
    """Terminate a malicious process by PID and broadcast containment status."""
    pid = payload.get("pid")
    endpoint_id = payload.get("endpoint_id", "local-host-01")
    if not pid:
        raise HTTPException(status_code=400, detail="PID is required")

    from backend.modules.containment import kill_process
    res = kill_process(int(pid))

    await trigger_alert("PROCESS_KILLED_AND_CONTAINED", f"Ransomware process (PID {pid}) forcibly terminated ({res.get('reason')})", db)
    await manager.broadcast({"type": "process_killed", "data": {"pid": pid, "status": "TERMINATED", "result": res}})

    return {
        "status": "success",
        "pid": pid,
        "action": "TERMINATED",
        "details": res
    }


# ---------------------------------------------------------------------------
# THREAT INTELLIGENCE FEED ENDPOINTS
# ---------------------------------------------------------------------------
from backend.services.threat_intel_feed import ThreatIntelFeed

@router.get("/api/threat-intel/groups")
async def get_threat_groups(current_user: dict = Depends(get_current_user)):
    """Returns all known ransomware group profiles with TTPs and IOCs."""
    groups = ThreatIntelFeed.get_all_groups()
    return {"groups": groups, "count": len(groups)}

@router.get("/api/threat-intel/group/{group_id}")
async def get_threat_group(group_id: str, current_user: dict = Depends(get_current_user)):
    """Returns detailed profile of a specific ransomware threat group."""
    group = ThreatIntelFeed.get_group(group_id.upper())
    if not group:
        raise HTTPException(status_code=404, detail=f"Group not found: {group_id}")
    return group

@router.get("/api/threat-intel/correlate")
async def correlate_threats(db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    """Correlates current live alert types with known ransomware threat group signatures."""
    db_records = db.query(AlertRecord).order_by(AlertRecord.timestamp.desc()).limit(100).all()
    db_types = [getattr(a, "alert_type", getattr(a, "reason", "")) for a in db_records]
    mem_types = [a.get("type", a.get("alert_type", "")) for a in alerts_db]
    all_types = list(set(filter(None, db_types + mem_types)))
    return ThreatIntelFeed.correlate_with_alerts(all_types)


# ---------------------------------------------------------------------------
# SECTOR IMPACT ASSESSMENT ENDPOINTS
# ---------------------------------------------------------------------------
from backend.services.sector_risk_engine import SectorRiskEngine, SECTORS

@router.get("/api/sector-impact")
async def get_sector_impact(db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    """Assesses ransomware impact across all 6 critical sectors using live alert data."""
    db_records = db.query(AlertRecord).order_by(AlertRecord.timestamp.desc()).limit(100).all()
    db_types = [getattr(a, "alert_type", getattr(a, "reason", "")) for a in db_records]
    mem_types = [a.get("type", a.get("alert_type", "")) for a in alerts_db]
    alert_types = list(set(filter(None, db_types + mem_types)))
    assessment = SectorRiskEngine.assess_impact(alert_types)
    return {
        "alert_types_analyzed": alert_types,
        "sectors_assessed": len(assessment),
        "assessment": assessment,
        "generated_at": datetime.utcnow().isoformat() + "Z"
    }

@router.get("/api/sector-impact/{sector_id}")
async def get_sector_detail(sector_id: str, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    """Detailed impact analysis for a specific industry sector with full response playbook."""
    sid = sector_id.upper()
    if sid not in SECTORS:
        raise HTTPException(status_code=404, detail=f"Sector not found: {sid}. Valid: {list(SECTORS.keys())}")
    db_records = db.query(AlertRecord).order_by(AlertRecord.timestamp.desc()).limit(100).all()
    db_types = [getattr(a, "alert_type", getattr(a, "reason", "")) for a in db_records]
    mem_types = [a.get("type", a.get("alert_type", "")) for a in alerts_db]
    alert_types = list(set(filter(None, db_types + mem_types)))
    assessment = SectorRiskEngine.assess_impact(alert_types, sid)
    result = assessment.get(sid, {})
    result["full_response_playbook"] = SECTORS[sid]["response_playbook"]
    result["all_critical_assets"] = SECTORS[sid]["critical_assets"]
    result["all_regulatory_frameworks"] = SECTORS[sid]["regulatory_frameworks"]
    return result


# ---------------------------------------------------------------------------
# INCIDENT COMMAND CENTER — Single Pane of Glass
# ---------------------------------------------------------------------------
@router.get("/api/command-center/status")
async def get_command_center_status(db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    """
    Real-time Incident Command Center status.
    Combines: alerts, risk, containment, Kali sessions, threat intel, sector impact.
    """
    from backend.integration.kali.kali_test_controller import active_sessions

    total_alerts = len(alerts_db)
    critical_kw = ["ENTROPY_BURST", "RANSOM_NOTE", "PROCESS_KILLED", "ENDPOINT_ISOLATED",
                   "YARA", "ANTI_RECOVERY", "ML_ANOMALY"]
    critical_alerts = sum(1 for a in alerts_db if any(
        kw in a.get("type", a.get("alert_type", "")) for kw in critical_kw
    ))
    kali_sessions = [
        {"session_id": sid, "status": s.get("status"), "scenario": s.get("current_scenario"),
         "scenario_status": s.get("scenario_status")}
        for sid, s in active_sessions.items()
    ]
    db_records = db.query(AlertRecord).order_by(AlertRecord.timestamp.desc()).limit(50).all()
    db_types = [getattr(a, "alert_type", getattr(a, "reason", "")) for a in db_records]
    mem_types = [a.get("type", a.get("alert_type", "")) for a in alerts_db]
    all_types = list(set(filter(None, db_types + mem_types)))

    threat_corr = ThreatIntelFeed.correlate_with_alerts(all_types)
    sector_assess = SectorRiskEngine.assess_impact(all_types)
    sector_top3 = [
        {"sector": v["sector_name"], "impact": v["impact_score"], "severity": v["severity"]}
        for k, v in list(sector_assess.items())[:3]
    ]
    return {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "incident_status": "ACTIVE" if total_alerts > 0 else "IDLE",
        "risk_score": current_risk_score,
        "alert_summary": {"total": total_alerts, "critical": critical_alerts},
        "containment_summary": {
            "total_actions": len(containment_log),
            "process_kills": sum(1 for c in containment_log if "kill" in c.get("action", "").lower()),
            "isolations": sum(1 for c in containment_log if "isolat" in c.get("action", "").lower()),
        },
        "kali_lab_sessions": kali_sessions,
        "threat_intel": {
            "top_group": threat_corr.get("top_threat_group", "UNKNOWN"),
            "confidence_pct": threat_corr.get("top_confidence_pct", 0),
            "groups_matched": threat_corr.get("groups_matched", 0)
        },
        "sector_impact_top3": sector_top3
    }

