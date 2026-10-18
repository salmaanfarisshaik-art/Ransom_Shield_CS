"""
RansomShield Threat Intelligence Feed
Provides real-world ransomware group profiles, TTPs, and live threat context.
Data based on publicly available CISA/FBI advisories and threat reports.
"""
from typing import Dict, Any, List
from datetime import datetime

THREAT_GROUPS = {
    "LOCKBIT_3": {
        "group_id": "LOCKBIT_3",
        "name": "LockBit 3.0 (Black)",
        "aliases": ["ABCD", "LockBit Black"],
        "threat_level": "CRITICAL",
        "active_since": "2019-09",
        "ransomware_family": "LockBit",
        "encryption_algo": "AES-256 + RSA-4096",
        "known_extensions": [".lockbit", ".lb3"],
        "primary_targets": ["Manufacturing", "Healthcare", "Finance", "Legal"],
        "initial_access_ttps": ["RDP Bruteforce", "Phishing", "VPN Exploit", "Supply Chain"],
        "lateral_movement": ["PsExec", "WMI", "RDP", "Cobalt Strike"],
        "defense_evasion": ["Process Injection", "Shadow Copy Deletion", "Disable AV"],
        "avg_dwell_time_days": 4,
        "avg_ransom_demand_usd": 5500000,
        "known_victims_count": 2000,
        "ioc_signatures": [
            "vssadmin delete shadows /all /quiet",
            "bcdedit /set {default} recoveryenabled No",
            ".lockbit extension",
            "Restore-My-Files.txt ransom note"
        ],
        "cisa_advisory": "AA23-165A",
        "color": "#dc2626",
        "icon": "🔴"
    },
    "CLOP": {
        "group_id": "CLOP",
        "name": "CL0P (Clop) Ransomware",
        "aliases": ["TA505", "FIN11"],
        "threat_level": "CRITICAL",
        "active_since": "2019-02",
        "ransomware_family": "Clop",
        "encryption_algo": "RC4 + AES",
        "known_extensions": [".clop", ".CIop"],
        "primary_targets": ["Healthcare", "Finance", "Technology", "Retail"],
        "initial_access_ttps": ["Zero-day exploits (MOVEit, GoAnywhere)", "Phishing"],
        "lateral_movement": ["Cobalt Strike", "Meterpreter", "TrueBot"],
        "defense_evasion": ["Signed Binaries", "Process Hollowing", "LSASS Dump"],
        "avg_dwell_time_days": 6,
        "avg_ransom_demand_usd": 3000000,
        "known_victims_count": 800,
        "ioc_signatures": [
            ".clop extension",
            "CIopReadMe.txt",
            "Signed malicious DLLs",
            "MOVEit/GoAnywhere exploitation artifacts"
        ],
        "cisa_advisory": "AA23-158A",
        "color": "#b91c1c",
        "icon": "🔴"
    },
    "BLACKCAT_ALPHV": {
        "group_id": "BLACKCAT_ALPHV",
        "name": "BlackCat (ALPHV)",
        "aliases": ["ALPHV", "Noberus"],
        "threat_level": "CRITICAL",
        "active_since": "2021-11",
        "ransomware_family": "BlackCat",
        "encryption_algo": "AES-256 (ChaCha20 variant)",
        "known_extensions": [".alphv", "randomized"],
        "primary_targets": ["Healthcare", "Government", "Critical Infrastructure", "Finance"],
        "initial_access_ttps": ["Stolen credentials", "Exchange exploit", "Phishing"],
        "lateral_movement": ["Cobalt Strike", "AnyDesk", "TeamViewer", "RDP"],
        "defense_evasion": ["Rust-based evasion", "MBR wiper", "Safe Mode Reboot"],
        "avg_dwell_time_days": 5,
        "avg_ransom_demand_usd": 4200000,
        "known_victims_count": 1000,
        "ioc_signatures": [
            "Rust compiled binary",
            "ALPHV-BLACKCAT ransom note",
            "ESXi targeting for VM encryption",
            "MBR modification artifacts"
        ],
        "cisa_advisory": "AA23-353A",
        "color": "#7f1d1d",
        "icon": "🔴"
    },
    "AKIRA": {
        "group_id": "AKIRA",
        "name": "Akira Ransomware",
        "aliases": ["Akira"],
        "threat_level": "HIGH",
        "active_since": "2023-03",
        "ransomware_family": "Akira",
        "encryption_algo": "ChaCha20",
        "known_extensions": [".akira"],
        "primary_targets": ["Education", "Manufacturing", "Healthcare", "SMB"],
        "initial_access_ttps": ["Cisco VPN exploit (CVE-2023-20269)", "RDP", "Phishing"],
        "lateral_movement": ["AnyDesk", "WinSCP", "Cobalt Strike"],
        "defense_evasion": ["PowerShell bypass", "WMI abuse", "Credential dumping"],
        "avg_dwell_time_days": 3,
        "avg_ransom_demand_usd": 1800000,
        "known_victims_count": 300,
        "ioc_signatures": [
            ".akira extension",
            "akira_readme.txt",
            "Cisco VPN exploitation",
            "C++ compiled binary"
        ],
        "cisa_advisory": "AA24-109A",
        "color": "#c2410c",
        "icon": "🟠"
    },
    "PLAY": {
        "group_id": "PLAY",
        "name": "Play Ransomware",
        "aliases": ["PlayCrypt"],
        "threat_level": "HIGH",
        "active_since": "2022-06",
        "ransomware_family": "Play",
        "encryption_algo": "AES-RSA Hybrid",
        "known_extensions": [".play"],
        "primary_targets": ["Government", "Critical Infrastructure", "Healthcare", "Finance"],
        "initial_access_ttps": ["ProxyNotShell (CVE-2022-41082)", "RDP", "Valid Accounts"],
        "lateral_movement": ["Cobalt Strike", "Metasploit", "Net localgroup"],
        "defense_evasion": ["AMSI bypass", "ETW patching", "Scheduled Tasks"],
        "avg_dwell_time_days": 5,
        "avg_ransom_demand_usd": 2200000,
        "known_victims_count": 400,
        "ioc_signatures": [
            ".play extension",
            "ReadMe.txt ransom note",
            "Intermittent encryption",
            "ProxyNotShell artifacts"
        ],
        "cisa_advisory": "AA23-352A",
        "color": "#1d4ed8",
        "icon": "🟡"
    }
}


class ThreatIntelFeed:
    """Provides threat intelligence correlation for RansomShield alerts."""

    @staticmethod
    def get_all_groups() -> List[Dict[str, Any]]:
        return list(THREAT_GROUPS.values())

    @staticmethod
    def get_group(group_id: str) -> Dict[str, Any]:
        return THREAT_GROUPS.get(group_id, {})

    @staticmethod
    def correlate_with_alerts(alert_types: List[str]) -> Dict[str, Any]:
        """
        Given observed alert types, correlate with known threat groups
        using IOC signature matching and TTP similarity scoring.
        """
        correlations = []
        alert_set = set(alert_types)

        # Define IOC → alert mapping
        ioc_alert_mapping = {
            "HIGH_ENTROPY_WRITE_DETECTED": ["LOCKBIT_3", "CLOP", "BLACKCAT_ALPHV", "AKIRA", "PLAY"],
            "RAPID_MASS_RENAME_DETECTED":  ["LOCKBIT_3", "CLOP", "BLACKCAT_ALPHV", "PLAY"],
            "ANTI_RECOVERY_BEHAVIOR":       ["LOCKBIT_3", "BLACKCAT_ALPHV"],
            "RANSOM_NOTE_CREATED":          ["LOCKBIT_3", "CLOP", "AKIRA", "PLAY"],
            "YARA_SHADOW_DELETION_DETECTED": ["LOCKBIT_3", "BLACKCAT_ALPHV"],
            "ML_ANOMALY_DETECTED":          ["LOCKBIT_3", "CLOP", "BLACKCAT_ALPHV", "AKIRA", "PLAY"],
            "BEACONING_PATTERN_DETECTED":   ["CLOP", "BLACKCAT_ALPHV"],
            "SUSPICIOUS_FILE_ENUMERATION":  ["LOCKBIT_3", "CLOP", "AKIRA", "PLAY"],
        }

        group_scores: Dict[str, int] = {gid: 0 for gid in THREAT_GROUPS}
        for alert in alert_set:
            for gid in ioc_alert_mapping.get(alert, []):
                group_scores[gid] += 1

        # Build correlation list sorted by score
        for gid, score in sorted(group_scores.items(), key=lambda x: x[1], reverse=True):
            if score == 0:
                continue
            group = THREAT_GROUPS[gid]
            max_possible = len([a for a in alert_set if gid in ioc_alert_mapping.get(a, [])])
            confidence = min(100, (score / max(1, len(THREAT_GROUPS[gid]["ioc_signatures"]))) * 100)
            correlations.append({
                "group_id": gid,
                "group_name": group["name"],
                "threat_level": group["threat_level"],
                "color": group["color"],
                "confidence_pct": round(confidence, 1),
                "matched_iocs": score,
                "avg_ransom_demand_usd": group["avg_ransom_demand_usd"],
                "avg_dwell_time_days": group["avg_dwell_time_days"],
                "cisa_advisory": group["cisa_advisory"],
                "primary_targets": group["primary_targets"],
                "initial_access_ttps": group["initial_access_ttps"][:3]
            })

        return {
            "correlation_run_at": datetime.utcnow().isoformat() + "Z",
            "alerts_analyzed": len(alert_set),
            "groups_matched": len(correlations),
            "top_threat_group": correlations[0]["group_name"] if correlations else "UNKNOWN",
            "top_confidence_pct": correlations[0]["confidence_pct"] if correlations else 0,
            "correlations": correlations
        }
