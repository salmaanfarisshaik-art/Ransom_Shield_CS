"""
RansomShield Multi-Evidence Correlation & Adaptive Risk Engine (Phase K & Phase O & Phase P)
Correlates signals across filesystem, process, network, Sysmon, YARA, memory, Volatility, and ML.
Calculates 4-tiered adaptive risk scores and generates relationship correlation graph JSON.
"""
from typing import List, Dict, Any
from datetime import datetime
from sqlalchemy.orm import Session
from backend.models.entities import (
    EvidenceRecord, RiskAssessmentRecord, AlertRecord, IncidentRecord, TimelineEventRecord
)

class CorrelationService:
    @staticmethod
    def correlate_evidence(db: Session, endpoint_id: str, process_instance_id: str = None) -> Dict[str, Any]:
        """
        Gathers evidence records for an endpoint/process and computes multi-signal correlation matrix.
        """
        query = db.query(EvidenceRecord).filter(EvidenceRecord.endpoint_id == endpoint_id)
        if process_instance_id:
            query = query.filter(EvidenceRecord.process_instance_id == process_instance_id)

        evidence_items = query.all()

        counts = {
            "FILESYSTEM": 0,
            "PROCESS": 0,
            "NETWORK": 0,
            "SYSMON": 0,
            "YARA": 0,
            "MEMORY": 0,
            "VOLATILITY": 0,
            "ML": 0,
            "HIGH_ENTROPY": 0,
            "RAPID_RENAME": 0
        }

        for ev in evidence_items:
            st = ev.source_type
            if st in counts:
                counts[st] += 1
            if "ENTROPY" in ev.event_type:
                counts["HIGH_ENTROPY"] += 1
            if "RENAME" in ev.event_type:
                counts["RAPID_RENAME"] += 1

        return {
            "endpoint_id": endpoint_id,
            "process_instance_id": process_instance_id,
            "evidence_count": len(evidence_items),
            "signal_counts": counts,
            "evidence_summary": [
                {
                    "evidence_id": e.evidence_id,
                    "source_type": e.source_type,
                    "event_type": e.event_type,
                    "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                    "classification": e.classification
                }
                for e in evidence_items[-10:] # last 10
            ]
        }

    @staticmethod
    def generate_correlation_graph(db: Session, endpoint_id: str) -> Dict[str, Any]:
        """
        Generates nodes and edges JSON for Phase P correlation graph visualization.
        """
        evidence_items = db.query(EvidenceRecord).filter(EvidenceRecord.endpoint_id == endpoint_id).all()
        alerts = db.query(AlertRecord).filter(AlertRecord.endpoint_id == endpoint_id).all()

        nodes = [
            {"id": endpoint_id, "label": f"Endpoint: {endpoint_id}", "type": "Endpoint"}
        ]
        edges = []

        added_nodes = {endpoint_id}

        for idx, ev in enumerate(evidence_items[-15:]):
            node_id = f"ev_{ev.evidence_id[:8]}"
            if node_id not in added_nodes:
                nodes.append({
                    "id": node_id,
                    "label": f"{ev.source_type}: {ev.event_type}",
                    "type": ev.source_type
                })
                added_nodes.add(node_id)

            edges.append({
                "source": endpoint_id,
                "target": node_id,
                "type": "OBSERVED_BY"
            })

            if ev.process_instance_id:
                proc_node = f"proc_{ev.process_instance_id[:8]}"
                if proc_node not in added_nodes:
                    nodes.append({
                        "id": proc_node,
                        "label": f"Proc: {ev.process_instance_id[:12]}",
                        "type": "ProcessInstance"
                    })
                    added_nodes.add(proc_node)
                edges.append({
                    "source": proc_node,
                    "target": node_id,
                    "type": "CONTRIBUTED_TO"
                })

        for alt in alerts[-5:]:
            alt_node = f"alt_{alt.alert_id[:8]}"
            if alt_node not in added_nodes:
                nodes.append({
                    "id": alt_node,
                    "label": f"Alert ({alt.severity}): {alt.reason[:25]}...",
                    "type": "Alert"
                })
                added_nodes.add(alt_node)
            edges.append({
                "source": endpoint_id,
                "target": alt_node,
                "type": "CORRELATED_WITH"
            })

        return {"nodes": nodes, "edges": edges}

class AdaptiveRiskEngine:
    @staticmethod
    def calculate_risk(
        db: Session,
        endpoint_id: str,
        process_instance_id: str = None,
        ml_score: int = 0
    ) -> RiskAssessmentRecord:
        
        correlation = CorrelationService.correlate_evidence(db, endpoint_id, process_instance_id)
        signals = correlation["signal_counts"]

        base_score = 0
        
        # Weighted multi-signal risk calculation
        base_score += min(signals["HIGH_ENTROPY"] * 15, 30)
        base_score += min(signals["RAPID_RENAME"] * 15, 30)
        base_score += 25 if signals["YARA"] > 0 else 0
        base_score += 20 if signals["VOLATILITY"] > 0 else 0
        base_score += 15 if signals["SYSMON"] > 0 else 0
        base_score += min(int(ml_score * 0.3), 30)

        final_score = min(max(base_score, 0), 100)

        # Map to risk level
        if final_score <= 24:
            level = "LOW"
        elif final_score <= 49:
            level = "MODERATE"
        elif final_score <= 74:
            level = "HIGH"
        else:
            level = "CRITICAL"

        assessment = RiskAssessmentRecord(
            endpoint_id=endpoint_id,
            process_instance_id=process_instance_id,
            timestamp=datetime.utcnow(),
            risk_score=final_score,
            risk_level=level,
            contributing_evidence=signals,
            model_outputs={"ml_score": ml_score, "evidence_count": correlation["evidence_count"]}
        )
        db.add(assessment)
        db.commit()
        db.refresh(assessment)

        return assessment
