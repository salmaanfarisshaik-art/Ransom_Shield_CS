"""
RansomShield Relational Database Entities (Phase A Requirements)
Includes 25+ models tracking telemetry, evidence, ML, risk, containment, and audit trails.
"""
from datetime import datetime
import uuid
from sqlalchemy import (
    Column, String, Integer, Float, Boolean, DateTime, Text, ForeignKey, JSON
)
from sqlalchemy.orm import relationship
from backend.database.connection import Base

def generate_uuid():
    return str(uuid.uuid4())

class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    username = Column(String(100), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), nullable=False, default="ANALYST") # ADMIN, ANALYST, VIEWER
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class SessionRecord(Base):
    __tablename__ = "sessions"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    session_token = Column(String(255), unique=True, nullable=False, index=True)
    session_type = Column(String(20), nullable=False, default="PRODUCTION") # PRODUCTION vs DECOY
    ip_address = Column(String(50))
    failed_attempts = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)

class Endpoint(Base):
    __tablename__ = "endpoints"

    endpoint_id = Column(String(100), primary_key=True)
    hostname = Column(String(100), nullable=False)
    os = Column(String(50), nullable=False)
    os_version = Column(String(100))
    agent_version = Column(String(50), default="1.0.0")
    ip_address = Column(String(50))
    status = Column(String(20), default="ONLINE") # ONLINE, OFFLINE, CONTAINED, DEGRADED
    last_seen = Column(DateTime, default=datetime.utcnow)
    registration_time = Column(DateTime, default=datetime.utcnow)
    health_status = Column(String(50), default="HEALTHY")

class ProcessRecord(Base):
    __tablename__ = "processes"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    endpoint_id = Column(String(100), ForeignKey("endpoints.endpoint_id"), nullable=False)
    name = Column(String(255), nullable=False)
    path = Column(String(1000))
    sha256 = Column(String(64))

class ProcessInstance(Base):
    __tablename__ = "process_instances"

    process_instance_id = Column(String(150), primary_key=True)
    endpoint_id = Column(String(100), ForeignKey("endpoints.endpoint_id"), nullable=False)
    pid = Column(Integer, nullable=False)
    creation_time = Column(DateTime, nullable=False)
    executable_path = Column(String(1000))
    command_line = Column(Text)
    parent_pid = Column(Integer)
    user = Column(String(100))
    status = Column(String(20), default="RUNNING") # RUNNING, TERMINATED, KILLED

class NetworkEvent(Base):
    __tablename__ = "network_events"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    endpoint_id = Column(String(100), ForeignKey("endpoints.endpoint_id"), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    process_instance_id = Column(String(150), ForeignKey("process_instances.process_instance_id"))
    source_ip = Column(String(50))
    source_port = Column(Integer)
    dest_ip = Column(String(50))
    dest_port = Column(Integer)
    protocol = Column(String(10))
    data_direction = Column(String(10)) # INBOUND, OUTBOUND
    bytes_transferred = Column(Integer, default=0)

class SysmonEventRecord(Base):
    __tablename__ = "sysmon_events"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    endpoint_id = Column(String(100), ForeignKey("endpoints.endpoint_id"), nullable=False)
    event_id = Column(Integer, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    process_instance_id = Column(String(150))
    source = Column(String(100))
    event_data = Column(JSON)

class FilesystemEventRecord(Base):
    __tablename__ = "filesystem_events"

    event_id = Column(String(36), primary_key=True, default=generate_uuid)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    endpoint_id = Column(String(100), ForeignKey("endpoints.endpoint_id"), nullable=False)
    process_instance_id = Column(String(150))
    operation = Column(String(20), nullable=False) # WRITE, RENAME, DELETE, CREATE
    file_path = Column(Text, nullable=False)
    old_path = Column(Text)
    new_path = Column(Text)
    entropy = Column(Float, default=0.0)
    entropy_threshold = Column(Float, default=7.5)
    extension = Column(String(20))
    classification = Column(String(50), default="OBSERVED") # OBSERVED, RANSOMWARE_LIKE_BEHAVIOR, CONTROLLED_TEST
    event_source = Column(String(50), default="fs_monitor")

class MemoryImageRecord(Base):
    __tablename__ = "memory_images"

    memory_image_id = Column(String(36), primary_key=True, default=generate_uuid)
    endpoint_id = Column(String(100), ForeignKey("endpoints.endpoint_id"), nullable=False)
    pid = Column(Integer, nullable=False)
    process_instance_id = Column(String(150))
    creation_time = Column(DateTime, default=datetime.utcnow)
    acquisition_time = Column(DateTime, default=datetime.utcnow)
    dump_type = Column(String(50), default="MiniDumpWithFullMemory")
    file_path = Column(Text, nullable=False)
    file_size = Column(Integer, default=0)
    sha256 = Column(String(64), nullable=False)
    collector = Column(String(50), default="Win32_MiniDumpWriteDump")
    status = Column(String(20), default="ACQUIRED") # ACQUIRED, ANALYZED, DELETED
    analysis_status = Column(String(50), default="PENDING")
    retention_policy = Column(String(20), default="TEMPORARY") # TEMPORARY, FORENSIC, RESEARCH

class YaraFindingRecord(Base):
    __tablename__ = "yara_findings"

    finding_id = Column(String(36), primary_key=True, default=generate_uuid)
    rule_id = Column(String(100), nullable=False)
    rule_name = Column(String(100), nullable=False)
    rule_version = Column(String(20), default="1.0.0")
    rule_hash = Column(String(64))
    scan_target = Column(Text)
    scan_time = Column(DateTime, default=datetime.utcnow)
    match_count = Column(Integer, default=0)
    matched_strings = Column(JSON)
    memory_image_id = Column(String(36), ForeignKey("memory_images.memory_image_id"))
    process_instance_id = Column(String(150))
    status = Column(String(20), default="MATCH") # MATCH, NO_MATCH, SCAN_FAILED, YARA_UNAVAILABLE

class VolatilityFindingRecord(Base):
    __tablename__ = "volatility_findings"

    finding_id = Column(String(36), primary_key=True, default=generate_uuid)
    volatility_version = Column(String(20), default="3.0")
    plugin = Column(String(100), nullable=False)
    command = Column(Text)
    execution_timestamp = Column(DateTime, default=datetime.utcnow)
    memory_image_id = Column(String(36), ForeignKey("memory_images.memory_image_id"))
    status = Column(String(20), default="SUCCESS") # SUCCESS, FAILED, UNAVAILABLE
    output_hash = Column(String(64))
    parsed_findings = Column(JSON)

class EvidenceRecord(Base):
    __tablename__ = "evidence"

    evidence_id = Column(String(36), primary_key=True, default=generate_uuid)
    endpoint_id = Column(String(100), ForeignKey("endpoints.endpoint_id"), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    source_type = Column(String(30), nullable=False) # FILESYSTEM, PROCESS, SYSMON, YARA, MEMORY, VOLATILITY, ML, etc.
    event_type = Column(String(50), nullable=False)
    process_instance_id = Column(String(150))
    artifact = Column(String(255))
    observed_value = Column(Text)
    provenance = Column(String(100))
    confidence = Column(Float, default=1.0)
    classification = Column(String(30), default="OBSERVED") # OBSERVED, DERIVED, PROBABLE, UNKNOWN, CONTROLLED_TEST, DECOY
    integrity_hash = Column(String(64))
    collection_status = Column(String(20), default="SUCCESS")

class MLPredictionRecord(Base):
    __tablename__ = "ml_predictions"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    model_id = Column(String(100), default="IsolationForest")
    model_version = Column(String(20), default="1.0.0")
    features = Column(JSON)
    prediction = Column(Integer) # 1 = normal, -1 = anomaly
    anomaly_score = Column(Float)
    timestamp = Column(DateTime, default=datetime.utcnow)
    endpoint_id = Column(String(100))
    process_instance_id = Column(String(150))

class RiskAssessmentRecord(Base):
    __tablename__ = "risk_assessments"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    endpoint_id = Column(String(100), ForeignKey("endpoints.endpoint_id"), nullable=False)
    process_instance_id = Column(String(150))
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    risk_score = Column(Integer, nullable=False)
    risk_level = Column(String(20), nullable=False) # LOW, MODERATE, HIGH, CRITICAL
    contributing_evidence = Column(JSON)
    model_outputs = Column(JSON)

class AlertRecord(Base):
    __tablename__ = "alerts"

    alert_id = Column(String(36), primary_key=True, default=generate_uuid)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    endpoint_id = Column(String(100), ForeignKey("endpoints.endpoint_id"), nullable=False)
    process_instance_id = Column(String(150))
    severity = Column(String(20), default="HIGH") # LOW, MEDIUM, HIGH, CRITICAL
    risk_score = Column(Integer, default=85)
    reason = Column(Text, nullable=False)
    evidence_ids = Column(JSON)
    status = Column(String(20), default="NEW") # NEW, ACKNOWLEDGED, INVESTIGATING, CONTAINED, RESOLVED, FALSE_POSITIVE
    incident_id = Column(String(36))
    alert_type = Column(String(100), default="SUSPICIOUS_BEHAVIOR")
    cpu_usage = Column(Float, default=0.0)
    ram_usage = Column(Float, default=0.0)


class IncidentRecord(Base):
    __tablename__ = "incidents"

    incident_id = Column(String(36), primary_key=True, default=generate_uuid)
    endpoint_id = Column(String(100), ForeignKey("endpoints.endpoint_id"), nullable=False)
    start_time = Column(DateTime, default=datetime.utcnow)
    end_time = Column(DateTime)
    severity = Column(String(20), default="HIGH")
    risk_score = Column(Integer, default=85)
    status = Column(String(20), default="ACTIVE") # ACTIVE, CONTAINED, RESOLVED, CLOSED
    attack_classification = Column(String(100), default="SUSPICIOUS_RANSOMWARE_BEHAVIOR")
    timeline_summary = Column(JSON)

class TimelineEventRecord(Base):
    __tablename__ = "timeline_events"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    incident_id = Column(String(36), ForeignKey("incidents.incident_id"))
    endpoint_id = Column(String(100), ForeignKey("endpoints.endpoint_id"))
    timestamp = Column(DateTime, nullable=False, index=True)
    event_type = Column(String(50), nullable=False)
    description = Column(Text, nullable=False)
    source_module = Column(String(50))
    raw_event_id = Column(String(100))

class ResponseActionRecord(Base):
    __tablename__ = "response_actions"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    timestamp = Column(DateTime, default=datetime.utcnow)
    endpoint_id = Column(String(100), ForeignKey("endpoints.endpoint_id"), nullable=False)
    action_type = Column(String(50), nullable=False) # PROCESS_KILL, NETWORK_ISOLATE, RESTORE
    process_instance_id = Column(String(150))
    trigger_reason = Column(Text)
    status = Column(String(20), default="SUCCESS") # SUCCESS, FAILED, PERMISSION_REQUIRED
    mode = Column(String(20), default="SIMULATED") # REAL vs SIMULATED
    operator = Column(String(100), default="SYSTEM")
    verification_details = Column(JSON)

class ChainOfCustodyRecord(Base):
    __tablename__ = "chain_of_custody"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    evidence_id = Column(String(36), ForeignKey("evidence.evidence_id"), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    action = Column(String(50), nullable=False) # CREATED, COLLECTED, HASHED, ANALYZED, ACCESSED, EXPORTED, REPORTED
    actor = Column(String(100), nullable=False)
    sha256 = Column(String(64), nullable=False)
    notes = Column(Text)

class AuditLogRecord(Base):
    __tablename__ = "audit_logs"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    actor = Column(String(100), nullable=False)
    role = Column(String(20), nullable=False)
    action = Column(String(100), nullable=False)
    target = Column(String(255))
    session_type = Column(String(20), default="PRODUCTION") # PRODUCTION vs DECOY
    ip_address = Column(String(50))
    result = Column(String(20), default="SUCCESS")

class ReportRecord(Base):
    __tablename__ = "reports"

    report_id = Column(String(36), primary_key=True, default=generate_uuid)
    incident_id = Column(String(36), ForeignKey("incidents.incident_id"))
    generated_at = Column(DateTime, default=datetime.utcnow)
    generating_user = Column(String(100), default="ANALYST")
    format = Column(String(10), default="PDF") # PDF, HTML, JSON
    file_path = Column(Text, nullable=False)
    sha256 = Column(String(64), nullable=False)
    download_count = Column(Integer, default=0)

class ReportDownloadRecord(Base):
    __tablename__ = "report_downloads"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    report_id = Column(String(36), ForeignKey("reports.report_id"), nullable=False)
    downloaded_at = Column(DateTime, default=datetime.utcnow)
    user_id = Column(String(100), nullable=False)
    ip_address = Column(String(50))

class DatasetVersionRecord(Base):
    __tablename__ = "dataset_versions"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    version = Column(String(20), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    num_samples = Column(Integer, default=0)
    description = Column(Text)
    sha256 = Column(String(64))

class ModelVersionRecord(Base):
    __tablename__ = "model_versions"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    model_name = Column(String(100), nullable=False)
    version = Column(String(20), nullable=False)
    trained_at = Column(DateTime, default=datetime.utcnow)
    hyperparameters = Column(JSON)
    metrics = Column(JSON)

class ExperimentRunRecord(Base):
    __tablename__ = "experiment_runs"

    experiment_id = Column(String(36), primary_key=True, default=generate_uuid)
    name = Column(String(100), nullable=False)
    baseline_tag = Column(String(10), nullable=False) # B1, B2, B3, B4, B5
    timestamp = Column(DateTime, default=datetime.utcnow)

class LabNode(Base):
    __tablename__ = "lab_nodes"

    lab_id = Column(String(36), primary_key=True, default=generate_uuid)
    source_name = Column(String(100), nullable=False, unique=True)
    source_type = Column(String(50), default="CONTROLLED_TEST_GENERATOR")
    target_endpoint_id = Column(String(100), ForeignKey("endpoints.endpoint_id"))
    authorized = Column(Boolean, default=True)
    ip_address = Column(String(50))
    last_seen = Column(DateTime, default=datetime.utcnow)
    status = Column(String(20), default="ONLINE") # ONLINE, OFFLINE, BUSY

class LabSession(Base):
    __tablename__ = "lab_sessions"

    session_id = Column(String(36), primary_key=True, default=generate_uuid)
    lab_id = Column(String(36), ForeignKey("lab_nodes.lab_id"), nullable=False)
    source_name = Column(String(100), nullable=False)
    target_endpoint_id = Column(String(100), nullable=False)
    current_scenario = Column(String(100))
    scenario_status = Column(String(30), default="IDLE") # IDLE, RUNNING, COMPLETED, STOPPED, FAILED
    started_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime)
    operator = Column(String(100), default="ANALYST")
    status = Column(String(20), default="ACTIVE") # ACTIVE, EXPIRED, TERMINATED

class TestScenarioModel(Base):
    __tablename__ = "test_scenarios"

    scenario_id = Column(String(100), primary_key=True)
    scenario_name = Column(String(100), nullable=False)
    description = Column(Text)
    expected_signals = Column(JSON)
    expected_risk_range = Column(String(50))
    expected_outcome = Column(String(100))
    safety_level = Column(String(20), default="SAFE_SIMULATION")

class EndpointHeartbeatRecord(Base):
    __tablename__ = "endpoint_heartbeats"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    endpoint_id = Column(String(100), ForeignKey("endpoints.endpoint_id"), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    cpu_percent = Column(Float, default=0.0)
    ram_percent = Column(Float, default=0.0)
    disk_usage = Column(Float, default=0.0)
    network_kbps = Column(Float, default=0.0)
    agent_status = Column(String(20), default="ONLINE")

class IsolationStateRecord(Base):
    __tablename__ = "isolation_states"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    endpoint_id = Column(String(100), ForeignKey("endpoints.endpoint_id"), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    isolation_mode = Column(String(30), default="SIMULATED") # SIMULATED, TEMPORARY, FORENSIC, RESEARCH
    is_isolated = Column(Boolean, default=False)
    applied_rules = Column(JSON)
    requested_by = Column(String(100), default="OPERATOR")
    incident_id = Column(String(36))
    verification_status = Column(String(30), default="VERIFIED")

    config = Column(JSON)
    metrics = Column(JSON) # Precision, Recall, F1, FPR, Latency, CPU, RAM
    status = Column(String(20), default="COMPLETED")
