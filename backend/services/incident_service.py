"""
RansomShield Persistent Alert, Incident & Unified Timeline Service (Phase Q & Phase R & Phase S)
Manages persistent alerts, groups alerts into incidents, and builds unified chronological timelines.
"""
from typing import List, Dict, Any
from datetime import datetime
from sqlalchemy.orm import Session
from backend.models.entities import (
    AlertRecord, IncidentRecord, TimelineEventRecord, EvidenceRecord
)

class IncidentService:
    @staticmethod
    def create_alert(
        db: Session,
        endpoint_id: str,
        reason: str,
        severity: str = "HIGH",
        risk_score: int = 85,
        process_instance_id: str = None,
        evidence_ids: list = None
    ) -> AlertRecord:
        
        alert = AlertRecord(
            timestamp=datetime.utcnow(),
            endpoint_id=endpoint_id,
            process_instance_id=process_instance_id,
            severity=severity,
            risk_score=risk_score,
            reason=reason,
            evidence_ids=evidence_ids or [],
            status="NEW"
        )
        db.add(alert)
        db.commit()
        db.refresh(alert)

        # Associate or create Incident
        active_incident = db.query(IncidentRecord).filter(
            IncidentRecord.endpoint_id == endpoint_id,
            IncidentRecord.status == "ACTIVE"
        ).first()

        if not active_incident:
            active_incident = IncidentRecord(
                endpoint_id=endpoint_id,
                start_time=datetime.utcnow(),
                severity=severity,
                risk_score=risk_score,
                status="ACTIVE",
                attack_classification="SUSPICIOUS_RANSOMWARE_BEHAVIOR",
                timeline_summary=[]
            )
            db.add(active_incident)
            db.commit()
            db.refresh(active_incident)

        alert.incident_id = active_incident.incident_id
        db.commit()

        # Add to timeline
        timeline_event = TimelineEventRecord(
            incident_id=active_incident.incident_id,
            endpoint_id=endpoint_id,
            timestamp=datetime.utcnow(),
            event_type="ALERT_GENERATED",
            description=f"[{severity}] {reason}",
            source_module="AlertEngine",
            raw_event_id=alert.alert_id
        )
        db.add(timeline_event)
        db.commit()

        return alert

    @staticmethod
    def add_timeline_event(
        db: Session,
        endpoint_id: str,
        event_type: str,
        description: str,
        source_module: str = "System",
        incident_id: str = None,
        raw_event_id: str = None,
        timestamp: datetime = None
    ) -> TimelineEventRecord:
        
        event = TimelineEventRecord(
            incident_id=incident_id,
            endpoint_id=endpoint_id,
            timestamp=timestamp or datetime.utcnow(),
            event_type=event_type,
            description=description,
            source_module=source_module,
            raw_event_id=raw_event_id
        )
        db.add(event)
        db.commit()
        db.refresh(event)
        return event

    @staticmethod
    def get_unified_timeline(db: Session, endpoint_id: str = None, incident_id: str = None) -> List[Dict[str, Any]]:
        query = db.query(TimelineEventRecord)
        if incident_id:
            query = query.filter(TimelineEventRecord.incident_id == incident_id)
        elif endpoint_id:
            query = query.filter(TimelineEventRecord.endpoint_id == endpoint_id)

        events = query.order_by(TimelineEventRecord.timestamp.asc()).all()

        return [
            {
                "id": e.id,
                "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                "event_type": e.event_type,
                "description": e.description,
                "source_module": e.source_module,
                "incident_id": e.incident_id,
                "endpoint_id": e.endpoint_id
            }
            for e in events
        ]
