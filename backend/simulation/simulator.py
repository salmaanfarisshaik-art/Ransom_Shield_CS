"""
BENIGN CONTROLLED RANSOMWARE BEHAVIOR SIMULATOR
-----------------------------------------------
This script is a non-malicious test simulator used strictly for
defensive cybersecurity research (RansomShield project). 
It generates synthetic behavior (high-entropy file writes, rapid file renames, scenario-based patterns)
to test detection algorithms under controlled research conditions.

It DOES NOT contain any real encryption payloads, does not exfiltrate data,
and operates EXCLUSIVELY inside a designated sandbox directory.

LABEL: CONTROLLED_TEST_RANSOMWARE_LIKE
"""

import os
import sys
import time
import argparse
import subprocess
from typing import Optional, Dict, Any

def generate_random_bytes(size: int) -> bytes:
    return os.urandom(size)

def setup_sandbox(sandbox_dir: str, num_files: int = 20):
    if not os.path.exists(sandbox_dir):
        os.makedirs(sandbox_dir)
    else:
        for f in os.listdir(sandbox_dir):
            try:
                os.remove(os.path.join(sandbox_dir, f))
            except Exception:
                pass
        
    print(f"[+] Setting up sandbox in {sandbox_dir} with {num_files} files...")
    for i in range(num_files):
        filepath = os.path.join(sandbox_dir, f"test_doc_{i}.txt")
        with open(filepath, 'w') as f:
            f.write("This is a normal text file used for testing.\n" * 100)

def simulate_encryption_behavior(sandbox_dir: str, scenario: str = "CASE-RS-03"):
    print(f"[+] [CONTROLLED_TEST_RANSOMWARE_LIKE] Starting simulated scenario {scenario} in {sandbox_dir}...")
    files = [os.path.join(sandbox_dir, f) for f in os.listdir(sandbox_dir) if os.path.isfile(os.path.join(sandbox_dir, f))]
    
    do_entropy = scenario in ["CASE-RS-01", "CASE-RS-03", "CASE-RS-04", "CASE-RS-05"]
    do_rename = scenario in ["CASE-RS-02", "CASE-RS-03", "CASE-RS-04", "CASE-RS-05"]
    do_spawn = scenario in ["CASE-RS-04", "CASE-RS-05"]

    if do_spawn:
        try:
            print("[*] Simulating controlled test process spawn (benign command)...")
            subprocess.Popen(["cmd.exe", "/c", "echo CONTROLLED_TEST_PROCESS_SPAWN"], stdout=subprocess.DEVNULL)
        except Exception:
            pass

    for filepath in files:
        if not filepath.endswith('.txt'):
            continue
            
        if do_entropy:
            print(f"[*] Overwriting {filepath} with high-entropy data...")
            with open(filepath, 'wb') as f:
                f.write(generate_random_bytes(4096))
        else:
            with open(filepath, 'a') as f:
                f.write("\nModifying file content without entropy surge.\n")
            
        if do_rename:
            new_filepath = filepath + ".locked"
            print(f"[*] Renaming {filepath} to {new_filepath}...")
            os.replace(filepath, new_filepath)
        
        time.sleep(0.05)
        
    print(f"[+] [CONTROLLED_TEST_RANSOMWARE_LIKE] Scenario {scenario} complete.")

class RansomwareSimulator:
    @staticmethod
    def run_scenario(sandbox_dir: str, scenario_id: str = "CASE-RS-03") -> Dict[str, Any]:
        sandbox_path = os.path.abspath(sandbox_dir)
        if 'sandbox' not in sandbox_path.lower() and 'test' not in sandbox_path.lower():
            raise ValueError("Sandbox path must contain 'sandbox' or 'test' to prevent execution on real directories.")

        setup_sandbox(sandbox_path)
        time.sleep(0.5)
        start = time.time()
        simulate_encryption_behavior(sandbox_path, scenario=scenario_id)
        duration = round(time.time() - start, 3)

        return {
            "status": "SUCCESS",
            "scenario": scenario_id,
            "label": "CONTROLLED_TEST_RANSOMWARE_LIKE",
            "sandbox_path": sandbox_path,
            "duration_seconds": duration
        }

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Benign Controlled Ransomware Behavior Simulator")
    parser.add_argument("--sandbox", type=str, required=True, help="Absolute path to sandbox directory")
    parser.add_argument("--scenario", type=str, default="CASE-RS-03", help="Scenario ID (CASE-RS-01 to CASE-RS-05)")
    args = parser.parse_args()
    
    res = RansomwareSimulator.run_scenario(args.sandbox, args.scenario)
    print(f"[+] Simulation Result: {res}")
