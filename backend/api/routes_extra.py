
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
