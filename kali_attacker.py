#!/usr/bin/env python3
"""
+==============================================================================+
|   RANSOMSHIELD â€” KALI LINUX ATTACKER AGENT                                  |
|   Controlled Security Test Generator                                         |
|   For Defensive Research Laboratory Use Only                                 |
+==============================================================================+

PURPOSE:
    Run this script FROM your Kali Linux machine (or locally) to simulate
    authorized ransomware-like attack patterns against the Windows RansomShield
    endpoint. All actions are SAFE, SANDBOXED, and CONTROLLED.

USAGE (from Kali Linux):
    python3 kali_attacker.py --api http://<WINDOWS_IP>:8000 --api-key changeme-in-production
    python3 kali_attacker.py --api http://192.168.1.100:8000 --scenario SCENARIO_7

USAGE (local simulation):
    python kali_attacker.py --api http://127.0.0.1:8000 --scenario SCENARIO_7 --auto

WHAT THIS DOES:
    1. Registers this machine as an authorized "Kali-Lab-01" test node
    2. Runs a predefined safe scenario (NO real malware, NO destructive actions)
    3. Sends alerts to the RansomShield dashboard in REAL TIME
    4. Generates a forensic report at the end

SCENARIOS:
    SCENARIO_1  - Benign network baseline          (LOW risk)
    SCENARIO_2  - Rapid file operation burst       (MODERATE risk)
    SCENARIO_3  - Controlled rename attack         (HIGH risk)
    SCENARIO_4  - High-entropy write simulation    (HIGH risk)
    SCENARIO_5  - Process behavior + YARA          (CRITICAL risk)
    SCENARIO_6  - Network anomaly / beaconing      (MODERATE-HIGH risk)
    SCENARIO_7  - FULL multi-vector attack         (CRITICAL risk) [DEFAULT]

SAFETY:
    This script does NOT:
    - Execute real ransomware
    - Encrypt any real user files
    - Execute arbitrary shell commands on the target
    - Perform any destructive operations

    All file operations happen in a local sandbox directory ONLY.
"""

import os
import sys
import json
import time
import math
import shutil
import argparse
import platform
import urllib.request
import urllib.error
from datetime import datetime

# â”€â”€ Configuration â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
DEFAULT_API   = "http://127.0.0.1:8000/api"
DEFAULT_KEY   = "changeme-in-production"
DEFAULT_SCENARIO = "SCENARIO_7"
KALI_LAB_ID  = "Kali-Lab-01"
SOURCE_NAME  = "Kali-Lab-01"

SANDBOX_DIR = os.path.abspath(os.path.join(
    os.path.dirname(__file__), "scratch", "KALI_ATTACKER_SANDBOX"
))

# â”€â”€ Terminal Colors â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def c(code): return f"\033[{code}m"
RESET = c("0"); RED = c("91"); GREEN = c("92"); YELLOW = c("93")
CYAN = c("96"); BOLD = c("1"); MAGENTA = c("95"); WHITE = c("97")

def banner(text, color=CYAN):
    w = 70
    print(f"\n{color}{BOLD}{'='*w}{RESET}")
    print(f"{color}{BOLD}  {text}{RESET}")
    print(f"{color}{BOLD}{'='*w}{RESET}\n")

def step(n, text):    print(f"\n{YELLOW}{BOLD}[STEP {n}]{RESET} {WHITE}{text}{RESET}")
def ok(text):         print(f"  {GREEN}[OK]{RESET} {text}")
def info(text):       print(f"  {CYAN}[i]{RESET}  {text}")
def warn(text):       print(f"  {YELLOW}[!]{RESET}  {text}")
def alert(text):      print(f"  {RED}{BOLD}[ALERT]{RESET} {text}")
def err(text):        print(f"  {RED}[ERR]{RESET} {text}")

# â”€â”€ HTTP Helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def api_get(url, key):
    req = urllib.request.Request(url, headers={"x-api-key": key})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())

def api_post(url, key, data):
    payload = json.dumps(data).encode()
    req = urllib.request.Request(
        url, data=payload,
        headers={"Content-Type": "application/json", "x-api-key": key},
        method="POST"
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())

def shannon_entropy(data: bytes) -> float:
    if not data: return 0.0
    freq = [0] * 256
    for b in data: freq[b] += 1
    n = len(data)
    return -sum((c/n)*math.log2(c/n) for c in freq if c > 0)

# â”€â”€ Pre-flight checks â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def check_api(api_base, key):
    try:
        api_get(f"{api_base}/endpoints", key)
        return True
    except Exception:
        return False

def check_kali_endpoints(api_base, key):
    try:
        result = api_get(f"{api_base}/lab/kali/scenarios", key)
        return result.get("count", 0) > 0
    except Exception:
        return False

# â”€â”€ Registration â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def register_kali_node(api_base, key, target_endpoint="local-host-01"):
    info(f"Registering Kali node: {SOURCE_NAME} â†’ target: {target_endpoint}")
    result = api_post(f"{api_base}/lab/kali/register", key, {
        "lab_id":           KALI_LAB_ID,
        "source_name":      SOURCE_NAME,
        "source_type":      "CONTROLLED_TEST_GENERATOR",
        "target_endpoint_id": target_endpoint,
        "authorized":       True,
        "operator":         "kali-analyst"
    })
    session_id = result.get("test_session_id")
    ok(f"Registered! Session ID: {BOLD}{session_id}{RESET}")
    ok(f"Session expires: {result.get('expires_at', 'N/A')}")
    return session_id

# â”€â”€ Scenario Runner â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def run_scenario(api_base, key, session_id, scenario_id, target_endpoint="local-host-01"):
    info(f"Dispatching scenario {BOLD}{scenario_id}{RESET} â†’ target endpoint: {target_endpoint}")
    info(">>> Watch the RansomShield Dashboard â€” alerts will appear in REAL TIME!")
    time.sleep(1)

    result = api_post(f"{api_base}/lab/kali/run", key, {
        "test_session_id":   session_id,
        "scenario_id":       scenario_id,
        "target_endpoint_id": target_endpoint
    })

    exec_data = result.get("execution", {})
    alerts_sent = exec_data.get("alerts_sent", 0)
    risk = exec_data.get("risk_level", "?")
    exec_ms = exec_data.get("execution_time_ms", 0)
    status = exec_data.get("status", "?")
    vectors = exec_data.get("vectors_tested", [])

    alert(f"Scenario COMPLETE: {status} | Risk Level: {BOLD}{risk}{RESET}")
    ok(f"Alerts pushed to dashboard: {BOLD}{alerts_sent}{RESET}")
    ok(f"Execution time: {exec_ms:.1f}ms")
    if vectors:
        ok(f"Vectors tested: {', '.join(vectors)}")
    return result

# â”€â”€ Local Sandbox Attack (runs on Kali itself for visual proof) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def run_local_sandbox_attack(sandbox_dir):
    """Performs real local file operations on Kali side for visual demonstration."""
    step("L", "LOCAL SANDBOX OPERATIONS (Kali-side visual proof)")
    info(f"Sandbox: {sandbox_dir}")

    if os.path.exists(sandbox_dir):
        shutil.rmtree(sandbox_dir)
    os.makedirs(sandbox_dir, exist_ok=True)

    # Create victim files
    files = []
    file_data = [
        ("invoice_Q3.txt",         "Invoice #INV-2025-5678\nAmount: $95,000"),
        ("employee_records.csv",   "ID,Name,Salary\n1001,Alice,95000"),
        ("patient_data.hl7",       "MSH|^~\\&|HOSP|...|Patient:John Doe"),
        ("financial_model.xlsx.txt","Q4 Revenue: $2.8M | EBITDA: 42%"),
        ("scada_config.ini",       "[SCADA]\nPLC_IP=192.168.10.5\nport=502"),
        ("db_backup_2025.sql.txt", "INSERT INTO users VALUES (1,'admin','hash')"),
        ("board_minutes.docx.txt", "Acquisition discussion: Target: $450M"),
        ("source_code.py.txt",     "# Proprietary algorithm v3.2\ndef encrypt():"),
    ]
    for fname, content in file_data:
        fp = os.path.join(sandbox_dir, fname)
        with open(fp, "w") as f:
            f.write(content + "\n")
        files.append(fp)
        print(f"    {GREEN}[FILE]{RESET} Created: {fname}")

    ok(f"Created {len(files)} victim files")
    time.sleep(0.5)

    # Simulate encryption (high-entropy overwrites)
    print(f"\n  {RED}[ENCRYPTING...]{RESET}")
    encrypted = []
    for i, fp in enumerate(files):
        data = os.urandom(4096 + i * 512)
        with open(fp, "wb") as f:
            f.write(data)
        ent = shannon_entropy(data)
        print(f"    {RED}[ENC]{RESET} {os.path.basename(fp)} | entropy={ent:.4f}")
        encrypted.append(fp)
        time.sleep(0.08)

    # Rename to .locked
    print(f"\n  {RED}[RENAMING to .locked]{RESET}")
    for fp in encrypted:
        new = fp + ".locked"
        os.rename(fp, new)
        print(f"    {RED}[LCK]{RESET} {os.path.basename(fp)} â†’ {os.path.basename(new)}")
        time.sleep(0.06)

    # Drop ransom note
    note = os.path.join(sandbox_dir, "README_DECRYPT.txt")
    with open(note, "w") as f:
        f.write("+====================================================+\n")
        f.write("|        YOUR FILES HAVE BEEN ENCRYPTED              |\n")
        f.write("|  Pay 3.5 Bitcoin to bc1q...xyz to recover them      |\n")
        f.write("|  Contact: decrypt@onion-mail.access                |\n")
        f.write("+====================================================+\n")
        f.write("[CONTROLLED_TEST by Kali-Lab-01 for RansomShield Demo]\n")
    alert(f"Ransom note dropped: {note}")

    ok(f"Local sandbox attack complete!")
    print(f"\n  {CYAN}[!] Check sandbox: {sandbox_dir}{RESET}")
    return len(files)

# â”€â”€ Generate Forensic Report â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def generate_report(api_base, key):
    try:
        result = api_post(f"{api_base}/reports/quick-generate", key, {})
        fp = result.get("file_path", "N/A")
        sha = result.get("sha256", "N/A")
        url = result.get("download_url", "")
        ok(f"Forensic PDF: {fp}")
        ok(f"SHA-256: {sha}")
        if url:
            ok(f"Download: http://{api_base.split('//')[1].split('/')[0]}{url}")
        return fp
    except Exception as e:
        warn(f"PDF report skipped: {e}")
        return None

# â”€â”€ Main â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def main():
    parser = argparse.ArgumentParser(
        description="RansomShield Kali Attacker Agent â€” Controlled Security Lab"
    )
    parser.add_argument("--api",      default=DEFAULT_API,      help="RansomShield API base URL")
    parser.add_argument("--api-key",  default=DEFAULT_KEY,       help="API key")
    parser.add_argument("--scenario", default=DEFAULT_SCENARIO,  help="Scenario ID to run")
    parser.add_argument("--target",   default="local-host-01",   help="Target endpoint ID")
    parser.add_argument("--auto",     action="store_true",        help="Skip ENTER prompts")
    parser.add_argument("--local-only", action="store_true",     help="Run local sandbox only (no API)")
    args = parser.parse_args()

    api_base = args.api
    if not api_base.endswith("/api"):
        api_base = api_base.rstrip("/") + "/api"

    banner("RANSOMSHIELD â€” KALI LINUX ATTACKER AGENT", RED)
    print(f"  {WHITE}Kali Node    :{RESET} {SOURCE_NAME}")
    print(f"  {WHITE}Target API   :{RESET} {api_base}")
    print(f"  {WHITE}Scenario     :{RESET} {BOLD}{args.scenario}{RESET}")
    print(f"  {WHITE}Target EP    :{RESET} {args.target}")
    print(f"  {WHITE}Platform     :{RESET} {platform.system()} {platform.release()}")
    print(f"  {WHITE}Started      :{RESET} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    warn("DEFENSIVE RESEARCH ONLY â€” NO REAL MALWARE â€” SAFE SIMULATION")
    warn("All alerts are controlled & monitored by RansomShield")

    if args.local_only:
        run_local_sandbox_attack(SANDBOX_DIR)
        banner("LOCAL SANDBOX ATTACK COMPLETE", GREEN)
        return

    # â”€â”€ Step 1: API Connectivity â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    step(1, "Pre-flight: Checking RansomShield API connectivity")
    if not check_api(api_base, args.api_key):
        err(f"Cannot reach RansomShield API at {api_base}")
        err("Start the backend: uvicorn backend.api.main:app --port 8000")
        sys.exit(1)
    ok("RansomShield API is ONLINE")

    # â”€â”€ Step 2: Check Kali endpoints â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    step(2, "Checking Kali Lab integration endpoints")
    if not check_kali_endpoints(api_base, args.api_key):
        err("Kali Lab endpoints not found. Ensure backend is updated.")
        sys.exit(1)
    ok("Kali Lab endpoints are AVAILABLE")

    info(f"Open dashboard: http://127.0.0.1:8080/dashboard.html")
    if not args.auto:
        try:
            input(f"\n  {YELLOW}Press ENTER when dashboard is open to BEGIN the attack...{RESET} ")
        except (EOFError, KeyboardInterrupt):
            pass
    else:
        print(f"\n  {CYAN}[AUTO MODE] Starting in 3 seconds...{RESET}")
        time.sleep(3)

    # â”€â”€ Step 3: Register Kali Node â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    step(3, "Registering Kali Lab node with RansomShield")
    session_id = register_kali_node(api_base, args.api_key, args.target)
    time.sleep(0.5)

    # â”€â”€ Step 4: Local Sandbox Attack (visual proof on Kali side) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    step(4, "Executing LOCAL sandbox attack (on this machine)")
    run_local_sandbox_attack(SANDBOX_DIR)
    time.sleep(1)

    # â”€â”€ Step 5: Remote Alert Dispatch â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    step(5, f"Dispatching scenario {args.scenario} to RansomShield endpoint")
    alert(">>> ALERTS ARE NOW FLOWING TO THE DASHBOARD IN REAL TIME <<<")
    run_scenario(api_base, args.api_key, session_id, args.scenario, args.target)
    time.sleep(1)

    # â”€â”€ Step 6: Forensic Report â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    step(6, "Requesting forensic PDF report generation")
    report = generate_report(api_base, args.api_key)

    # â”€â”€ Summary â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    banner("KALI ATTACK SIMULATION COMPLETE", GREEN)
    print(f"  {GREEN}[OK]{RESET} Session ID       : {BOLD}{session_id}{RESET}")
    print(f"  {GREEN}[OK]{RESET} Scenario run      : {BOLD}{args.scenario}{RESET}")
    print(f"  {GREEN}[OK]{RESET} Dashboard alerts  : LIVE at http://127.0.0.1:8080/dashboard.html")
    print(f"  {GREEN}[OK]{RESET} Sandbox files     : {SANDBOX_DIR}")
    if report:
        print(f"  {GREEN}[OK]{RESET} Forensic report   : {report}")
    print()
    print(f"  {WHITE}WHAT WAS DEMONSTRATED:{RESET}")
    print(f"    â†’ Kali Linux acting as an authorized red-team test generator")
    print(f"    â†’ Real file operations (encrypt, rename, ransom note) on sandbox")
    print(f"    â†’ Real-time alert pipeline: Kali â†’ API â†’ WebSocket â†’ Dashboard")
    print(f"    â†’ RBAC-enforced session management with TTL and authorization checks")
    print(f"    â†’ Forensic PDF with SHA-256 integrity hash preserved")
    print()

if __name__ == "__main__":
    main()

