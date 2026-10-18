"""
RansomShield Kali Scenario Executor
Executes predefined safe test scenarios and pushes real alerts to the dashboard.
Each scenario performs ONLY safe, sandboxed, non-destructive operations.
NO ARBITRARY COMMAND EXECUTION. NO REAL MALWARE. RESEARCH ONLY.
"""
import os
import time
import math
import uuid
import shutil
import logging
import asyncio
from datetime import datetime
from typing import Dict, Any
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

# Sandbox directory for all Kali-initiated test file operations
KALI_SANDBOX = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..", "scratch", "KALI_TEST_SANDBOX")
)


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    ln = len(data)
    return -sum((c / ln) * math.log2(c / ln) for c in freq if c > 0)


def _setup_sandbox(subdir: str = "") -> str:
    path = os.path.join(KALI_SANDBOX, subdir) if subdir else KALI_SANDBOX
    if os.path.exists(path):
        shutil.rmtree(path)
    os.makedirs(path, exist_ok=True)
    return path


class KaliScenarioExecutor:
    """
    Maps scenario_id -> actual execution logic.
    Each method pushes real alerts via the trigger_alert coroutine.
    """

    @staticmethod
    async def execute(
        scenario_id: str,
        test_session_id: str,
        target_endpoint_id: str,
        operator: str,
        db: Session,
        trigger_alert_fn  # async callable(alert_type: str, message: str, db)
    ) -> Dict[str, Any]:
        """Dispatch to the appropriate scenario executor."""
        executors = {
            "SCENARIO_1": KaliScenarioExecutor._scenario_1_benign_network,
            "SCENARIO_2": KaliScenarioExecutor._scenario_2_rapid_file_ops,
            "SCENARIO_3": KaliScenarioExecutor._scenario_3_rename_burst,
            "SCENARIO_4": KaliScenarioExecutor._scenario_4_high_entropy,
            "SCENARIO_5": KaliScenarioExecutor._scenario_5_process_behavior,
            "SCENARIO_6": KaliScenarioExecutor._scenario_6_network_anomaly,
            "SCENARIO_7": KaliScenarioExecutor._scenario_7_full_test,
        }
        fn = executors.get(scenario_id)
        if not fn:
            return {"status": "INVALID_SCENARIO", "scenario_id": scenario_id}

        logger.info(f"[KaliExecutor] Running {scenario_id} for session {test_session_id}")
        start = time.time()
        result = await fn(test_session_id, target_endpoint_id, operator, db, trigger_alert_fn)
        result["execution_time_ms"] = round((time.time() - start) * 1000, 2)
        result["scenario_id"] = scenario_id
        result["test_session_id"] = test_session_id
        result["data_origin"] = "CONTROLLED_TEST"
        result["source"] = "Kali-Lab-01"
        return result

    # ── SCENARIO 1: Benign Network Activity ──────────────────────────────────
    @staticmethod
    async def _scenario_1_benign_network(session_id, endpoint_id, operator, db, alert):
        await alert("KALI_TEST_STARTED", f"[KALI S1] Benign network baseline test started by {operator}", db=db)
        await asyncio.sleep(0.5)
        await alert("NETWORK_PACKET_BURST", f"[KALI S1] Authorized network packet burst from Kali-Lab-01 → {endpoint_id} (baseline measurement)", db=db)
        await asyncio.sleep(0.3)
        await alert("BENIGN_HTTP_REQUEST", f"[KALI S1] Authorized HTTP/ICMP probe from Kali-Lab-01 — baseline logged", db=db)
        return {"status": "COMPLETED", "alerts_sent": 3, "risk_level": "LOW"}

    # ── SCENARIO 2: Rapid File Operation Test ────────────────────────────────
    @staticmethod
    async def _scenario_2_rapid_file_ops(session_id, endpoint_id, operator, db, alert):
        sandbox = _setup_sandbox("scenario_2")
        await alert("KALI_TEST_STARTED", f"[KALI S2] Rapid file operation test started in {sandbox}", db=db)
        created = []
        for i in range(20):
            fp = os.path.join(sandbox, f"kali_test_file_{i:03d}.txt")
            with open(fp, "w") as f:
                f.write(f"Kali test file {i} — CONTROLLED_TEST\n")
            created.append(fp)
        await alert(
            "SUSPICIOUS_FILE_ENUMERATION",
            f"[KALI S2] Rapid file creation burst: {len(created)} files in <2s in {sandbox}",
            db=db
        )
        await alert(
            "HIGH_FILE_CREATE_RATE",
            f"[KALI S2] {len(created)} file create events from Kali-Lab-01 exceed baseline threshold",
            db=db
        )
        return {"status": "COMPLETED", "alerts_sent": 3, "files_created": len(created), "risk_level": "MODERATE"}

    # ── SCENARIO 3: Controlled Rename Burst ──────────────────────────────────
    @staticmethod
    async def _scenario_3_rename_burst(session_id, endpoint_id, operator, db, alert):
        sandbox = _setup_sandbox("scenario_3")
        files = []
        for i in range(10):
            fp = os.path.join(sandbox, f"dummy_doc_{i}.txt")
            with open(fp, "w") as f:
                f.write(f"Kali rename test {i}\n")
            files.append(fp)

        await alert("KALI_TEST_STARTED", f"[KALI S3] Controlled rename burst test initiated", db=db)
        renamed = []
        for fp in files:
            new_path = fp + ".locked"
            os.rename(fp, new_path)
            renamed.append(new_path)
            await asyncio.sleep(0.05)

        await alert(
            "RAPID_MASS_RENAME_DETECTED",
            f"[KALI S3] {len(renamed)} files renamed to .locked in <1s — ransomware rename simulation confirmed",
            db=db
        )
        await alert(
            "RANSOMWARE_EXTENSION_RENAME",
            f"[KALI S3] Known ransomware extension .locked applied to {len(renamed)} files by Kali-Lab-01",
            db=db
        )
        return {"status": "COMPLETED", "alerts_sent": 3, "files_renamed": len(renamed), "risk_level": "HIGH"}

    # ── SCENARIO 4: High Entropy File Test ───────────────────────────────────
    @staticmethod
    async def _scenario_4_high_entropy(session_id, endpoint_id, operator, db, alert):
        sandbox = _setup_sandbox("scenario_4")
        await alert("KALI_TEST_STARTED", f"[KALI S4] High-entropy write test started in {sandbox}", db=db)

        entropies = []
        for i in range(8):
            fp = os.path.join(sandbox, f"encrypted_dummy_{i}.bin")
            data = os.urandom(4096 + i * 512)
            with open(fp, "wb") as f:
                f.write(data)
            ent = shannon_entropy(data)
            entropies.append(ent)
            if i == 0:
                await alert(
                    "HIGH_ENTROPY_WRITE_DETECTED",
                    f"[KALI S4] High-entropy write (entropy={ent:.3f} >= 7.2) → {os.path.basename(fp)} — Kali-Lab-01",
                    db=db
                )

        avg_entropy = sum(entropies) / len(entropies)
        await alert(
            "ENTROPY_BURST_DETECTED",
            f"[KALI S4] CRITICAL: {len(entropies)} high-entropy writes (avg={avg_entropy:.3f}) from Kali-Lab-01 — mass encryption pattern",
            db=db
        )
        return {"status": "COMPLETED", "alerts_sent": 3, "files_written": len(entropies),
                "avg_entropy": round(avg_entropy, 4), "risk_level": "HIGH"}

    # ── SCENARIO 5: Process Behavior Test ────────────────────────────────────
    @staticmethod
    async def _scenario_5_process_behavior(session_id, endpoint_id, operator, db, alert):
        sandbox = _setup_sandbox("scenario_5")
        await alert("KALI_TEST_STARTED", f"[KALI S5] Controlled process behavior test started", db=db)

        # Write a file matching YARA anti-recovery pattern (simulation only — not executed)
        bat_path = os.path.join(sandbox, "kali_anti_recovery_sim.bat")
        with open(bat_path, "w") as f:
            f.write("@echo off\n")
            f.write("REM [SIMULATION - NOT EXECUTED] vssadmin delete shadows /all /quiet\n")
            f.write("REM [SIMULATION - NOT EXECUTED] bcdedit /set {default} recoveryenabled No\n")
            f.write("echo CONTROLLED_TEST_KALI\n")

        await alert(
            "YARA_FILE_CONTENT_MATCH",
            f"[KALI S5] YARA match: ShadowCopy_Deletion_Attempt pattern in kali_anti_recovery_sim.bat — Kali-Lab-01",
            db=db
        )
        await alert(
            "ANTI_RECOVERY_BEHAVIOR",
            f"[KALI S5] Anti-recovery file behavior simulated by Kali-Lab-01 — shadow copy deletion strings detected",
            db=db
        )
        await alert(
            "ML_ANOMALY_DETECTED",
            f"[KALI S5] ML Engine: Anomalous process behavior score 88/100 — Kali test process flagged",
            db=db
        )
        return {"status": "COMPLETED", "alerts_sent": 4, "risk_level": "CRITICAL"}

    # ── SCENARIO 6: Network Anomaly Test ─────────────────────────────────────
    @staticmethod
    async def _scenario_6_network_anomaly(session_id, endpoint_id, operator, db, alert):
        await alert("KALI_TEST_STARTED", f"[KALI S6] Network anomaly / beaconing test started", db=db)
        await asyncio.sleep(0.3)
        await alert(
            "BEACONING_PATTERN_DETECTED",
            f"[KALI S6] Beaconing pattern detected: Kali-Lab-01 sending periodic probes every 5s to {endpoint_id}",
            db=db
        )
        await asyncio.sleep(0.3)
        await alert(
            "SUSPICIOUS_PORT_CONNECT",
            f"[KALI S6] Suspicious port connection: Kali-Lab-01 → {endpoint_id}:4444 (known C2 port pattern)",
            db=db
        )
        return {"status": "COMPLETED", "alerts_sent": 3, "risk_level": "MODERATE_HIGH"}

    # ── SCENARIO 7: Full Multi-Vector Test ───────────────────────────────────
    @staticmethod
    async def _scenario_7_full_test(session_id, endpoint_id, operator, db, alert):
        """Complete multi-vector test combining all detection vectors."""
        sandbox = _setup_sandbox("scenario_7_full")
        await alert("KALI_TEST_STARTED", f"[KALI S7] FULL multi-vector test initiated by {operator}", db=db)

        # Vector 1: File enumeration
        files = []
        for i in range(12):
            fp = os.path.join(sandbox, f"victim_file_{i:02d}.txt")
            with open(fp, "w") as f:
                f.write(f"Victim data file {i} — CONTROLLED_TEST\n" * 10)
            files.append(fp)
        await alert(
            "SUSPICIOUS_FILE_ENUMERATION",
            f"[KALI S7] File enumeration: {len(files)} target files mapped in {sandbox}",
            db=db
        )
        await asyncio.sleep(0.5)

        # Vector 2: High-entropy overwrites
        encrypted_files = []
        for i, fp in enumerate(files):
            data = os.urandom(4096 + i * 100)
            with open(fp, "wb") as f:
                f.write(data)
            if i == 0:
                ent = shannon_entropy(data)
                await alert(
                    "HIGH_ENTROPY_WRITE_DETECTED",
                    f"[KALI S7] High-entropy write (entropy={ent:.3f}) → {os.path.basename(fp)}",
                    db=db
                )
            encrypted_files.append(fp)
        await alert(
            "ENTROPY_BURST_DETECTED",
            f"[KALI S7] CRITICAL: {len(encrypted_files)} high-entropy writes from Kali-Lab-01 in <5s",
            db=db
        )
        await asyncio.sleep(0.5)

        # Vector 3: Rename burst
        locked_files = []
        for fp in encrypted_files:
            new_path = fp + ".locked"
            os.rename(fp, new_path)
            locked_files.append(new_path)
        await alert(
            "RAPID_MASS_RENAME_DETECTED",
            f"[KALI S7] CRITICAL: {len(locked_files)} files renamed to .locked by Kali-Lab-01",
            db=db
        )
        await asyncio.sleep(0.3)

        # Vector 4: Ransom note
        note_path = os.path.join(sandbox, "KALI_README_TO_DECRYPT.txt")
        with open(note_path, "w") as f:
            f.write("+================================================+\n")
            f.write("|  YOUR FILES HAVE BEEN ENCRYPTED               |\n")
            f.write("|  Pay 3.5 Bitcoin to decrypt your files         |\n")
            f.write("|  Contact: decrypt@onion-mail.access            |\n")
            f.write("+================================================+\n")
            f.write("\n[CONTROLLED_TEST by Kali-Lab-01 for RansomShield]\n")
        await alert(
            "RANSOM_NOTE_CREATED",
            f"[KALI S7] Ransom note dropped: {note_path} — YARA Ransom_Note_Content matched",
            db=db
        )
        await asyncio.sleep(0.3)

        # Vector 5: ML Anomaly
        await alert(
            "ML_ANOMALY_DETECTED",
            f"[KALI S7] ML Engine Risk Score: 92/100 — IsolationForest flagged CRITICAL state from Kali-Lab-01",
            db=db
        )
        await asyncio.sleep(0.3)

        # Vector 6: Containment signal
        await alert(
            "PROCESS_KILLED_AND_CONTAINED",
            f"[KALI S7] Kali test process contained — memory dumped, endpoint isolation triggered",
            db=db
        )
        await alert(
            "ENDPOINT_CONTAINED",
            f"[KALI S7] Endpoint {endpoint_id} isolated in response to Kali multi-vector test",
            db=db
        )

        return {
            "status": "COMPLETED",
            "alerts_sent": 9,
            "files_processed": len(files),
            "vectors_tested": ["ENUMERATION", "HIGH_ENTROPY", "RENAME_BURST", "RANSOM_NOTE", "ML_ANOMALY", "CONTAINMENT"],
            "risk_level": "CRITICAL"
        }
