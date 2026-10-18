"""
RansomShield Unified Evidence & Chain-of-Custody Service (Phase J & Phase W)
Handles SHA-256 calculation, evidence persistence, provenance tracking, and chain-of-custody logging.
"""
import hashlib
import json
from datetime import datetime
from sqlalchemy.orm import Session
from backend.models.entities import EvidenceRecord, ChainOfCustodyRecord, AuditLogRecord

def compute_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def compute_file_sha256(filepath: str) -> str:
    try:
        hasher = hashlib.sha256()
        with open(filepath, 'rb') as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception:
        return "0" * 64

class EvidenceService:
    @staticmethod
    def record_evidence(
        db: Session,
        endpoint_id: str,
        source_type: str,
        event_type: str,
        observed_value: str,
        process_instance_id: str = None,
        artifact: str = None,
        provenance: str = "Host Collector",
        confidence: float = 1.0,
        classification: str = "OBSERVED", # OBSERVED, DERIVED, PROBABLE, UNKNOWN, CONTROLLED_TEST, DECOY
        actor: str = "SYSTEM"
    ) -> EvidenceRecord:
        
        raw_bytes = f"{endpoint_id}:{source_type}:{event_type}:{observed_value}:{datetime.utcnow().isoformat()}".encode('utf-8')
        integrity_hash = compute_sha256(raw_bytes)

        evidence = EvidenceRecord(
            endpoint_id=endpoint_id,
            timestamp=datetime.utcnow(),
            source_type=source_type,
            event_type=event_type,
            process_instance_id=process_instance_id,
            artifact=artifact,
            observed_value=observed_value,
            provenance=provenance,
            confidence=confidence,
            classification=classification,
            integrity_hash=integrity_hash,
            collection_status="SUCCESS"
        )
        db.add(evidence)
        db.commit()
        db.refresh(evidence)

        # Log Chain of Custody CREATED event
        coc = ChainOfCustodyRecord(
            evidence_id=evidence.evidence_id,
            timestamp=datetime.utcnow(),
            action="CREATED",
            actor=actor,
            sha256=integrity_hash,
            notes=f"Evidence collected via {source_type} ({event_type})"
        )
        db.add(coc)
        db.commit()

        return evidence

    @staticmethod
    def log_chain_of_custody(
        db: Session,
        evidence_id: str,
        action: str, # CREATED, COLLECTED, HASHED, ANALYZED, ACCESSED, EXPORTED, REPORTED
        actor: str,
        sha256: str,
        notes: str = None
    ) -> ChainOfCustodyRecord:
        coc = ChainOfCustodyRecord(
            evidence_id=evidence_id,
            timestamp=datetime.utcnow(),
            action=action,
            actor=actor,
            sha256=sha256,
            notes=notes
        )
        db.add(coc)
        db.commit()
        db.refresh(coc)
        return coc
