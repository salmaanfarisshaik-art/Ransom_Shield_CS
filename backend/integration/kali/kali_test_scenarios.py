"""
RansomShield Controlled Security Test Scenarios Registry
Predefined safe test definitions for Kali Linux test generator.
NO REAL MALWARE. NO DESTRUCTIVE PAYLOADS. NO ARBITRARY COMMAND EXECUTION.
"""
from typing import Dict, Any, List

SCENARIOS: Dict[str, Dict[str, Any]] = {
    "SCENARIO_1": {
        "scenario_id": "SCENARIO_1",
        "scenario_name": "BENIGN_NETWORK_ACTIVITY",
        "description": "Generates authorized benign HTTP/ICMP traffic to test network observer baseline.",
        "expected_signals": ["NETWORK_PACKET_BURST", "BENIGN_HTTP_REQUEST"],
        "expected_risk_range": "LOW (0-20)",
        "expected_outcome": "BASELINE_LOGGED",
        "safety_level": "SAFE_BENIGN"
    },
    "SCENARIO_2": {
        "scenario_id": "SCENARIO_2",
        "scenario_name": "RAPID_FILE_OPERATION_TEST",
        "description": "Performs rapid benign text file creation to test file system event rate observers.",
        "expected_signals": ["SUSPICIOUS_FILE_ENUMERATION", "HIGH_FILE_CREATE_RATE"],
        "expected_risk_range": "MODERATE (25-45)",
        "expected_outcome": "ENUMERATION_ALERT",
        "safety_level": "SAFE_SIMULATION"
    },
    "SCENARIO_3": {
        "scenario_id": "SCENARIO_3",
        "scenario_name": "CONTROLLED_RENAME_BURST",
        "description": "Simulates rapid extension modification (.locked) on safe dummy files.",
        "expected_signals": ["RAPID_MASS_RENAME_DETECTED", "RANSOMWARE_EXTENSION_RENAME"],
        "expected_risk_range": "HIGH (65-80)",
        "expected_outcome": "RENAME_BURST_ALERT",
        "safety_level": "SAFE_SIMULATION"
    },
    "SCENARIO_4": {
        "scenario_id": "SCENARIO_4",
        "scenario_name": "CONTROLLED_HIGH_ENTROPY_FILE_TEST",
        "description": "Writes pseudo-random high-entropy bytes to safe dummy files in target sandbox.",
        "expected_signals": ["HIGH_ENTROPY_WRITE_DETECTED", "ENTROPY_BURST_DETECTED"],
        "expected_risk_range": "HIGH (75-85)",
        "expected_outcome": "HIGH_ENTROPY_ALERT",
        "safety_level": "SAFE_SIMULATION"
    },
    "SCENARIO_5": {
        "scenario_id": "SCENARIO_5",
        "scenario_name": "CONTROLLED_PROCESS_BEHAVIOR_TEST",
        "description": "Launches a dummy process displaying suspicious handle burst and anti-recovery strings.",
        "expected_signals": ["YARA_FILE_CONTENT_MATCH", "ANTI_RECOVERY_BEHAVIOR", "ML_ANOMALY_DETECTED"],
        "expected_risk_range": "CRITICAL (85-95)",
        "expected_outcome": "CRITICAL_PROCESS_ALERT",
        "safety_level": "SAFE_SIMULATION"
    },
    "SCENARIO_6": {
        "scenario_id": "SCENARIO_6",
        "scenario_name": "CONTROLLED_NETWORK_ANOMALY_TEST",
        "description": "Simulates beaconing / C2 telemetry patterns over synthetic sockets.",
        "expected_signals": ["BEACONING_PATTERN_DETECTED", "SUSPICIOUS_PORT_CONNECT"],
        "expected_risk_range": "MODERATE_HIGH (50-70)",
        "expected_outcome": "NETWORK_ANOMALY_ALERT",
        "safety_level": "SAFE_SIMULATION"
    },
    "SCENARIO_7": {
        "scenario_id": "SCENARIO_7",
        "scenario_name": "FULL_RANSHIELD_CONTROLLED_TEST",
        "description": "Executes full multi-vector test sequence (Enumeration + High Entropy + Rename Burst + Ransom Note + ML Anomaly + Containment).",
        "expected_signals": [
            "SUSPICIOUS_FILE_ENUMERATION",
            "HIGH_ENTROPY_WRITE_DETECTED",
            "ENTROPY_BURST_DETECTED",
            "RAPID_MASS_RENAME_DETECTED",
            "RANSOM_NOTE_CREATED",
            "YARA_FILE_CONTENT_MATCH",
            "ML_ANOMALY_DETECTED",
            "PROCESS_KILLED_AND_CONTAINED",
            "ENDPOINT_CONTAINED"
        ],
        "expected_risk_range": "CRITICAL (90-100)",
        "expected_outcome": "FULL_CONTAINMENT_TRIGGERED",
        "safety_level": "SAFE_SIMULATION"
    }
}

def get_scenario(scenario_id: str) -> Dict[str, Any]:
    return SCENARIOS.get(scenario_id, None)

def list_scenarios() -> List[Dict[str, Any]]:
    return list(SCENARIOS.values())
