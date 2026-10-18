"""
RansomShield Sector Risk Intelligence Engine
Maps detected ransomware behavior to real-world sector impact assessments.
Covers: Healthcare, Finance, Critical Infrastructure, Education, Government, Manufacturing
"""
from typing import Dict, Any, List
from datetime import datetime

# ── Sector Definitions ─────────────────────────────────────────────────────
SECTORS = {
    "HEALTHCARE": {
        "name": "Healthcare & Medical",
        "icon": "local_hospital",
        "color": "#ef4444",
        "critical_assets": [
            "Patient records (PHI/HIPAA)", "EMR/EHR systems", "PACS imaging systems",
            "Medical IoT devices", "ICU monitoring", "Pharmacy dispensing systems"
        ],
        "regulatory_frameworks": ["HIPAA", "HITECH", "FDA 21 CFR Part 11"],
        "avg_ransom_paid_usd": 1270000,
        "avg_downtime_days": 19,
        "life_safety_risk": True,
        "breach_notification_hours": 60,
        "priority_iocs": [
            "RAPID_MASS_RENAME_DETECTED", "HIGH_ENTROPY_WRITE_DETECTED",
            "RANSOM_NOTE_CREATED", "ANTI_RECOVERY_BEHAVIOR"
        ],
        "response_playbook": [
            "1. IMMEDIATELY isolate affected systems from medical network",
            "2. Activate BCP — switch to paper-based procedures",
            "3. Notify CISO, CEO, and legal within 15 minutes",
            "4. Engage FBI and CISA within 1 hour",
            "5. Contact cyber insurance provider",
            "6. Preserve all evidence (do NOT power off systems)",
            "7. Notify HHS/OCR within 60 hours if PHI breached",
            "8. Coordinate with backup facility if patient transfers needed"
        ],
        "impact_multiplier": 3.5
    },
    "FINANCE": {
        "name": "Financial Services & Banking",
        "icon": "account_balance",
        "color": "#f59e0b",
        "critical_assets": [
            "Core banking systems", "SWIFT/wire transfer infrastructure",
            "Trading platforms", "Customer PII/PCI data", "ATM networks"
        ],
        "regulatory_frameworks": ["PCI-DSS", "SOX", "GLBA", "DORA (EU)", "RBI Guidelines"],
        "avg_ransom_paid_usd": 2340000,
        "avg_downtime_days": 16,
        "life_safety_risk": False,
        "breach_notification_hours": 72,
        "priority_iocs": [
            "SUSPICIOUS_FILE_ENUMERATION", "HIGH_ENTROPY_WRITE_DETECTED",
            "RAPID_MASS_RENAME_DETECTED", "BEACONING_PATTERN_DETECTED"
        ],
        "response_playbook": [
            "1. Trigger Incident Response Plan Level 3",
            "2. Suspend all non-essential outbound financial transactions",
            "3. Notify CISO, Board Risk Committee immediately",
            "4. Engage FinCEN, OCC, Federal Reserve (as applicable)",
            "5. Freeze affected accounts — prevent fraudulent transfers",
            "6. Notify customers within regulatory deadline",
            "7. Coordinate with SWIFT ISAC if interbank systems affected",
            "8. File SAR (Suspicious Activity Report) if required"
        ],
        "impact_multiplier": 4.2
    },
    "CRITICAL_INFRASTRUCTURE": {
        "name": "Critical Infrastructure (ICS/SCADA)",
        "icon": "electrical_services",
        "color": "#dc2626",
        "critical_assets": [
            "SCADA/PLC controllers", "Power grid management", "Water treatment systems",
            "Pipeline control systems", "Nuclear facility controls", "Traffic systems"
        ],
        "regulatory_frameworks": ["NERC CIP", "IEC 62443", "NIST SP 800-82", "CISA Framework"],
        "avg_ransom_paid_usd": 4100000,
        "avg_downtime_days": 21,
        "life_safety_risk": True,
        "breach_notification_hours": 1,
        "priority_iocs": [
            "HIGH_ENTROPY_WRITE_DETECTED", "ANTI_RECOVERY_BEHAVIOR",
            "RAPID_MASS_RENAME_DETECTED", "ML_ANOMALY_DETECTED"
        ],
        "response_playbook": [
            "1. EMERGENCY: Switch to manual operational mode immediately",
            "2. Air-gap OT network from IT network — physical disconnection",
            "3. Notify CISA Emergency Line: 1-888-282-0870 within 1 HOUR",
            "4. Activate government CIRCIA reporting obligation",
            "5. Engage FBI Cyber Division",
            "6. Alert downstream consumers / grid operators",
            "7. Coordinate with DHS/ICS-CERT",
            "8. DO NOT pay ransom — escalate to national security level"
        ],
        "impact_multiplier": 5.0
    },
    "GOVERNMENT": {
        "name": "Government & Public Sector",
        "icon": "account_balance",
        "color": "#7c3aed",
        "critical_assets": [
            "Citizen PII databases", "Tax/revenue systems", "Law enforcement databases",
            "Emergency services", "Voting infrastructure", "Social services systems"
        ],
        "regulatory_frameworks": ["FedRAMP", "FISMA", "NIST 800-53", "StateRAMP", "SLED"],
        "avg_ransom_paid_usd": 740000,
        "avg_downtime_days": 23,
        "life_safety_risk": False,
        "breach_notification_hours": 72,
        "priority_iocs": [
            "SUSPICIOUS_FILE_ENUMERATION", "RAPID_MASS_RENAME_DETECTED",
            "RANSOM_NOTE_CREATED", "PROCESS_KILLED_AND_CONTAINED"
        ],
        "response_playbook": [
            "1. Activate Government Continuity of Operations Plan (COOP)",
            "2. Notify Agency CISO and Inspector General immediately",
            "3. Contact CISA within 72 hours — file mandatory report",
            "4. Preserve evidence for law enforcement chain of custody",
            "5. Notify affected citizens per state breach notification law",
            "6. Coordinate with MS-ISAC (Multi-State ISAC)",
            "7. Brief elected officials and prepare public communications",
            "8. Engage National Guard Cyber Unit if state-level"
        ],
        "impact_multiplier": 3.0
    },
    "EDUCATION": {
        "name": "Education & Research",
        "icon": "school",
        "color": "#0ea5e9",
        "critical_assets": [
            "Student PII/FERPA data", "Research data & IP", "LMS platforms",
            "Financial aid systems", "HR/payroll", "Library archives"
        ],
        "regulatory_frameworks": ["FERPA", "COPPA", "GLBA (for financial aid)", "State laws"],
        "avg_ransom_paid_usd": 462000,
        "avg_downtime_days": 14,
        "life_safety_risk": False,
        "breach_notification_hours": 72,
        "priority_iocs": [
            "HIGH_ENTROPY_WRITE_DETECTED", "SUSPICIOUS_FILE_ENUMERATION",
            "RAPID_MASS_RENAME_DETECTED"
        ],
        "response_playbook": [
            "1. Isolate affected systems — maintain student-facing services if possible",
            "2. Notify President/Chancellor and Legal Counsel",
            "3. Alert Department of Education if Title IV funds affected",
            "4. Notify students/parents per FERPA if records breached",
            "5. Engage REN-ISAC (Research and Education Network ISAC)",
            "6. Preserve research data backups — coordinate with Research Office",
            "7. Communicate with faculty and students transparently"
        ],
        "impact_multiplier": 2.0
    },
    "MANUFACTURING": {
        "name": "Manufacturing & Industry 4.0",
        "icon": "factory",
        "color": "#f97316",
        "critical_assets": [
            "Production line automation", "ERP/SAP systems", "Supply chain data",
            "Industrial IoT sensors", "Quality control systems", "IP/trade secrets"
        ],
        "regulatory_frameworks": ["NIST CSF", "IEC 62443", "ISO 27001", "CMMC"],
        "avg_ransom_paid_usd": 1640000,
        "avg_downtime_days": 12,
        "life_safety_risk": False,
        "breach_notification_hours": 72,
        "priority_iocs": [
            "HIGH_ENTROPY_WRITE_DETECTED", "RAPID_MASS_RENAME_DETECTED",
            "ANTI_RECOVERY_BEHAVIOR", "ML_ANOMALY_DETECTED"
        ],
        "response_playbook": [
            "1. Halt production lines — switch to manual operations",
            "2. Notify CISO, COO, and Supply Chain Manager",
            "3. Alert key customers and suppliers of potential delays",
            "4. Engage Insurance carrier — activate business interruption claim",
            "5. Assess inventory and production impact",
            "6. Engage MFG-ISAC for threat intelligence sharing",
            "7. Coordinate with Tier-1/2 suppliers on data exposure"
        ],
        "impact_multiplier": 2.8
    }
}


class SectorRiskEngine:
    """Analyzes alert patterns and maps them to sector-specific impact assessments."""

    @staticmethod
    def assess_impact(alerts: List[str], sector_id: str = None) -> Dict[str, Any]:
        """
        Given a list of alert types, assess the real-world impact across all sectors
        or a specific sector.
        """
        alert_set = set(alerts)
        results = {}
        sectors_to_check = [sector_id] if sector_id else list(SECTORS.keys())

        for sid in sectors_to_check:
            sector = SECTORS.get(sid)
            if not sector:
                continue

            # Count IOC hits
            ioc_hits = [ioc for ioc in sector["priority_iocs"] if ioc in alert_set]
            hit_ratio = len(ioc_hits) / len(sector["priority_iocs"]) if sector["priority_iocs"] else 0

            # Calculate impact score
            base_impact = hit_ratio * 100
            weighted_impact = min(100, base_impact * sector["impact_multiplier"] / 3.5)

            # Estimate financial exposure
            est_cost = sector["avg_ransom_paid_usd"] * hit_ratio

            # Determine severity level
            if weighted_impact >= 80:
                severity = "CRITICAL"
            elif weighted_impact >= 60:
                severity = "HIGH"
            elif weighted_impact >= 40:
                severity = "MODERATE"
            elif weighted_impact >= 20:
                severity = "LOW"
            else:
                severity = "MINIMAL"

            results[sid] = {
                "sector_id": sid,
                "sector_name": sector["name"],
                "icon": sector["icon"],
                "color": sector["color"],
                "ioc_hits": ioc_hits,
                "hit_count": len(ioc_hits),
                "total_priority_iocs": len(sector["priority_iocs"]),
                "impact_score": round(weighted_impact, 1),
                "severity": severity,
                "estimated_cost_usd": round(est_cost),
                "avg_downtime_days": sector["avg_downtime_days"],
                "life_safety_risk": sector["life_safety_risk"],
                "regulatory_frameworks": sector["regulatory_frameworks"],
                "breach_notification_hours": sector["breach_notification_hours"],
                "response_playbook": sector["response_playbook"],
                "critical_assets_at_risk": sector["critical_assets"][:3],  # Top 3
                "assessed_at": datetime.utcnow().isoformat() + "Z"
            }

        # Sort by impact score
        sorted_results = dict(sorted(results.items(), key=lambda x: x[1]["impact_score"], reverse=True))
        return sorted_results

    @staticmethod
    def get_sector(sector_id: str) -> Dict[str, Any]:
        return SECTORS.get(sector_id, {})

    @staticmethod
    def list_sectors() -> List[str]:
        return list(SECTORS.keys())
