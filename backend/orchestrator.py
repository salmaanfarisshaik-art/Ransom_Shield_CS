"""
RansomShield Real-Time Attack Detection Orchestrator
====================================================
This module runs on your REAL machine, watching REAL directories, and detecting
REAL ransomware-like behavior using actual Shannon entropy, YARA, and process monitoring.

What is REAL here:
  - The directory monitoring (watchdog on real OS file system)
  - Shannon entropy calculation on actual file bytes
  - Extension rename tracking on real disk events
  - Process CPU/disk sampling from your actual running processes
  - YARA scanning of actual file data against real ransomware patterns
  - Alert generation pushed to the live backend API

What is CONTROLLED (not actual malware):
  - The "attacker" used in live demos is a safe simulator (writes random bytes)
  - We do NOT ship or execute actual ransomware binaries

Run this in one terminal:
    python -m backend.orchestrator

Then in ANOTHER terminal, trigger the controlled simulation:
    python -m backend.simulation.simulator --sandbox ./scratch/live_test --scenario CASE-RS-05

Watch the dashboard at http://127.0.0.1:8080/dashboard.html — alerts will appear LIVE.
"""

import os
import sys
import json
import time
import math
import psutil
import threading
import urllib.request
import urllib.error
import subprocess
from datetime import datetime
from collections import deque
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    print("[ORCHESTRATOR] WARNING: yara-python not installed. YARA scanning disabled.")

# ──────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────
API_BASE = "http://127.0.0.1:8000/api"
API_KEY = "changeme-in-production"

# Real directories to watch — add your own important folders here
# For live demo: watches the sandbox AND user desktop/documents
WATCH_DIRS = [
    os.path.abspath("./scratch"),           # Demo sandbox
    os.path.expanduser("~/Desktop"),        # Real desktop
    os.path.expanduser("~/Documents"),      # Real documents
]

# YARA rules path
YARA_RULES_PATH = os.path.join(os.path.dirname(__file__), "data", "rules", "generic_ransom_behavior.yar")

# Thresholds
ENTROPY_THRESHOLD = 7.2          # Shannon entropy > 7.2 = likely encrypted/compressed
RENAME_THRESHOLD = 5             # 5+ renames in time window = suspicious
RENAME_WINDOW_SECS = 10          # Time window for rapid rename detection
ENTROPY_BURST_THRESHOLD = 3      # 3+ high-entropy writes in window = suspicious

# Suspicious extensions that ransomware uses
RANSOMWARE_EXTENSIONS = {
    '.locked', '.encrypted', '.enc', '.crypt', '.crypted',
    '.WNCRY', '.wncryt', '.RYK', '.lockbit', '.conti',
    '.revil', '.sodinokibi', '.blackbasta', '.darkside',
    '.DHARMA', '.adobe', '.onion', '.ransom', '.cryptowall'
}

# ──────────────────────────────────────────────
# YARA Engine (Real-world rules)
# ──────────────────────────────────────────────
compiled_yara_rules = None
if YARA_AVAILABLE and os.path.exists(YARA_RULES_PATH):
    try:
        compiled_yara_rules = yara.compile(filepath=YARA_RULES_PATH)
        print(f"[ORCHESTRATOR] YARA rules compiled from: {YARA_RULES_PATH}")
    except Exception as e:
        print(f"[ORCHESTRATOR] WARNING: Failed to compile YARA rules: {e}")

# ──────────────────────────────────────────────
# Alert Push to Backend API
# ──────────────────────────────────────────────
def push_alert(alert_type: str, message: str, severity: str = "HIGH"):
    """Push real-time alert to the RansomShield backend API."""
    try:
        payload = json.dumps({
            "alert_type": alert_type,
            "message": message
        }).encode('utf-8')
        req = urllib.request.Request(
            f"{API_BASE}/internal/alert",
            data=payload,
            headers={
                "Content-Type": "application/json",
                "x-api-key": API_KEY
            },
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            pass
        print(f"\n{'='*60}")
        print(f"[🚨 ALERT FIRED] {alert_type}")
        print(f"  Message: {message}")
        print(f"  Time:    {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*60}")
    except urllib.error.URLError:
        # Backend offline — log locally
        print(f"[ALERT - NO API] {alert_type}: {message}")

# ──────────────────────────────────────────────
# Shannon Entropy Calculator
# ──────────────────────────────────────────────
def calculate_entropy(filepath: str) -> float:
    """Calculate real Shannon entropy of actual file bytes."""
    try:
        with open(filepath, 'rb') as f:
            data = f.read(65536)  # Read up to 64KB for performance
        if not data:
            return 0.0
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1
        length = len(data)
        entropy = 0.0
        for count in freq:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return entropy
    except Exception:
        return 0.0

# ──────────────────────────────────────────────
# YARA Scanner (Real ransomware pattern matching)
# ──────────────────────────────────────────────
def yara_scan_file(filepath: str) -> list:
    """Scan a real file against real ransomware YARA rules."""
    if not compiled_yara_rules:
        return []
    try:
        matches = compiled_yara_rules.match(filepath, timeout=5)
        return [m.rule for m in matches]
    except Exception:
        return []

def yara_scan_data(data: bytes) -> list:
    """Scan raw byte data against real ransomware YARA rules."""
    if not compiled_yara_rules:
        return []
    try:
        matches = compiled_yara_rules.match(data=data, timeout=5)
        return [m.rule for m in matches]
    except Exception:
        return []

# ──────────────────────────────────────────────
# Real-Time Process Monitor
# ──────────────────────────────────────────────
class ProcessMonitor:
    """Monitors real running processes for suspicious behavior."""
    SUSPICIOUS_CMDLINES = [
        "vssadmin delete shadows",
        "vssadmin.exe delete",
        "wmic shadowcopy delete",
        "bcdedit /set",
        "wbadmin delete catalog",
        "recoveryenabled No",
        "bootstatuspolicy ignoreallfailures",
        "net stop",
        "sc delete",
        "icacls * /grant",
    ]

    def __init__(self):
        self._running = True
        self._thread = None

    def start(self):
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        print("[ORCHESTRATOR] Process monitor started — watching real running processes")

    def stop(self):
        self._running = False

    def _monitor_loop(self):
        seen_pids = set()
        while self._running:
            try:
                for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'cpu_percent', 'create_time']):
                    try:
                        info = proc.info
                        pid = info['pid']
                        name = info.get('name', '')
                        cmdline = ' '.join(info.get('cmdline') or []).lower()

                        # Check against suspicious command-line patterns
                        for suspicious in self.SUSPICIOUS_CMDLINES:
                            if suspicious.lower() in cmdline and pid not in seen_pids:
                                seen_pids.add(pid)
                                push_alert(
                                    "SUSPICIOUS_PROCESS_CMDLINE",
                                    f"REAL THREAT: Process '{name}' (PID: {pid}) executing: {cmdline[:100]}"
                                )

                        # YARA-scan the process name itself
                        if name:
                            yara_matches = yara_scan_data(name.encode())
                            if yara_matches and pid not in seen_pids:
                                seen_pids.add(pid)
                                push_alert(
                                    "YARA_PROCESS_MATCH",
                                    f"YARA match on process '{name}' (PID: {pid}): {yara_matches}"
                                )

                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue

            except Exception as e:
                pass
            time.sleep(3)  # Check every 3 seconds

# ──────────────────────────────────────────────
# Real-Time Filesystem Event Handler
# ──────────────────────────────────────────────
class RealRansomwareDetector(FileSystemEventHandler):
    """
    Watchdog event handler that performs REAL detection:
    - Real Shannon entropy on real file bytes
    - Real YARA scanning against real ransomware rules
    - Real extension monitoring for known ransomware extensions
    - Real rapid-rename burst detection
    """

    def __init__(self):
        self.rename_events = deque()
        self.entropy_events = deque()
        self._lock = threading.Lock()

    def _cleanup_window(self, current_time):
        with self._lock:
            while self.rename_events and current_time - self.rename_events[0] > RENAME_WINDOW_SECS:
                self.rename_events.popleft()
            while self.entropy_events and current_time - self.entropy_events[0] > RENAME_WINDOW_SECS:
                self.entropy_events.popleft()

    def on_moved(self, event):
        """Detect real extension renames like .txt -> .locked"""
        if event.is_directory:
            return

        src = event.src_path
        dst = event.dest_path
        dst_ext = os.path.splitext(dst)[1].lower()

        # Check if renamed to a known ransomware extension
        if dst_ext in RANSOMWARE_EXTENSIONS or dst_ext == '.locked':
            push_alert(
                "RANSOMWARE_EXTENSION_RENAME",
                f"🚨 REAL DETECTION: File renamed to ransomware extension '{dst_ext}': {src} → {dst}"
            )

        # Track for rapid rename burst
        current_time = time.time()
        self._cleanup_window(current_time)
        with self._lock:
            self.rename_events.append(current_time)
            count = len(self.rename_events)

        if count >= RENAME_THRESHOLD:
            push_alert(
                "RAPID_MASS_RENAME_DETECTED",
                f"🚨 REAL DETECTION: {count} files renamed in {RENAME_WINDOW_SECS}s — mass rename attack pattern detected! Last: {src}"
            )
            with self._lock:
                self.rename_events.clear()

        # YARA scan the filename/path
        yara_matches = yara_scan_data(dst.encode())
        if yara_matches:
            push_alert(
                "YARA_FILENAME_MATCH",
                f"YARA pattern match on filename '{os.path.basename(dst)}': Rules={yara_matches}"
            )

    def on_modified(self, event):
        """Detect real high-entropy file writes (encryption indicators)"""
        if event.is_directory:
            return

        filepath = event.src_path
        if not os.path.exists(filepath):
            return

        # Skip very small files and system files
        try:
            size = os.path.getsize(filepath)
            if size < 512:
                return
        except Exception:
            return

        # Calculate REAL Shannon entropy on REAL file bytes
        time.sleep(0.05)  # Let the write complete
        entropy = calculate_entropy(filepath)

        if entropy >= ENTROPY_THRESHOLD:
            push_alert(
                "HIGH_ENTROPY_WRITE_DETECTED",
                f"🚨 REAL DETECTION: High-entropy write detected (entropy={entropy:.4f} ≥ {ENTROPY_THRESHOLD}) → {filepath}"
            )

            # Track entropy burst
            current_time = time.time()
            self._cleanup_window(current_time)
            with self._lock:
                self.entropy_events.append(current_time)
                count = len(self.entropy_events)

            if count >= ENTROPY_BURST_THRESHOLD:
                push_alert(
                    "ENTROPY_BURST_DETECTED",
                    f"🚨 REAL DETECTION: {count} high-entropy writes in {RENAME_WINDOW_SECS}s — mass encryption attack pattern! Threshold exceeded."
                )
                with self._lock:
                    self.entropy_events.clear()

            # YARA scan the actual file content
            yara_matches = yara_scan_file(filepath)
            if yara_matches:
                push_alert(
                    "YARA_FILE_CONTENT_MATCH",
                    f"🚨 YARA match in file '{os.path.basename(filepath)}': Rules={yara_matches}"
                )

    def on_created(self, event):
        """Detect ransomware note files being created"""
        if event.is_directory:
            return

        filepath = event.src_path
        filename = os.path.basename(filepath).upper()

        # Ransom note filenames
        ransom_note_names = {
            'README.TXT', 'HOW_TO_DECRYPT.TXT', 'RESTORE_FILES.TXT',
            'YOUR_FILES_ARE_ENCRYPTED.TXT', 'DECRYPT_INSTRUCTION.TXT',
            'HELP_DECRYPT.HTML', 'HOW_TO_BUY_DECRYPTOR.TXT',
            'README_TO_DECRYPT.TXT', 'LOCKBIT_RANSOMWARE.HTA',
            '!README!.TXT', '#DECRYPT_MY_FILES#.TXT', 'RYUKREADME.TXT'
        }

        if filename in ransom_note_names:
            push_alert(
                "RANSOM_NOTE_CREATED",
                f"🚨 CRITICAL: Ransom note file created: {filepath}"
            )

        # Scan newly created file with YARA
        time.sleep(0.1)
        if os.path.exists(filepath):
            yara_matches = yara_scan_file(filepath)
            if yara_matches:
                push_alert(
                    "YARA_FILE_CONTENT_MATCH",
                    f"🚨 YARA match in newly created file '{filename}': Rules={yara_matches}"
                )


# ──────────────────────────────────────────────
# System Resource Monitor (feeds real ML engine)
# ──────────────────────────────────────────────
class SystemResourceMonitor:
    """Continuously samples real system CPU and disk metrics and sends to ML API."""

    def __init__(self):
        self._running = True
        self._alert_count = 0
        self._thread = None

    def increment_alert(self):
        self._alert_count += 1

    def start(self):
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        print("[ORCHESTRATOR] System resource monitor started — real CPU/Disk sampling")

    def stop(self):
        self._running = False

    def _monitor_loop(self):
        while self._running:
            try:
                # REAL CPU and disk metrics from your actual machine
                cpu = psutil.cpu_percent(interval=1)
                disk_io = psutil.disk_io_counters()
                disk_write_mb = 0.0
                if disk_io:
                    disk_write_mb = disk_io.write_bytes / (1024 * 1024)

                payload = json.dumps({
                    "cpu_percent": cpu,
                    "disk_write_mb_per_s": disk_write_mb,
                    "memory_percent": psutil.virtual_memory().percent,
                    "fs_alert_count": self._alert_count
                }).encode()

                req = urllib.request.Request(
                    f"{API_BASE}/internal/sys_metrics",
                    data=payload,
                    headers={"Content-Type": "application/json", "x-api-key": API_KEY},
                    method="POST"
                )
                with urllib.request.urlopen(req, timeout=3) as resp:
                    result = json.loads(resp.read())
                    risk = result.get("risk_score_updated_to", 0)
                    if risk > 70:
                        print(f"[ML ENGINE] ⚠️  Anomaly detected! Risk Score: {risk}/100 | CPU: {cpu}% | Disk Write: {disk_write_mb:.1f} MB/s")

            except urllib.error.URLError:
                pass  # Backend not yet available
            except Exception as e:
                pass

            time.sleep(2)


# ──────────────────────────────────────────────
# Main Orchestrator
# ──────────────────────────────────────────────
def main():
    print("\n" + "="*65)
    print("   RansomShield Real-Time Detection Orchestrator")
    print("   Monitoring REAL directories on your REAL machine")
    print("="*65)

    # Ensure sandbox dir exists
    os.makedirs("./scratch", exist_ok=True)

    # 1. Start filesystem watchdog on all configured directories
    handler = RealRansomwareDetector()
    observer = Observer()
    for watch_dir in WATCH_DIRS:
        if os.path.exists(watch_dir):
            observer.schedule(handler, watch_dir, recursive=True)
            print(f"[ORCHESTRATOR] 👁️  Watching: {watch_dir}")
        else:
            os.makedirs(watch_dir, exist_ok=True)
            observer.schedule(handler, watch_dir, recursive=True)
            print(f"[ORCHESTRATOR] 📁  Created and watching: {watch_dir}")
    observer.start()

    # 2. Start real process monitor
    proc_monitor = ProcessMonitor()
    proc_monitor.start()

    # 3. Start real system resource monitor (feeds ML engine)
    resource_monitor = SystemResourceMonitor()
    resource_monitor.start()

    print(f"\n[ORCHESTRATOR] ✅ All detection engines active!")
    print(f"[ORCHESTRATOR] 📊 Dashboard: http://127.0.0.1:8080/dashboard.html")
    print(f"[ORCHESTRATOR] 🎯 To test LIVE detection, run in another terminal:")
    print(f"   python -m backend.simulation.simulator --sandbox ./scratch/live_test --scenario CASE-RS-05")
    print(f"\n[ORCHESTRATOR] Watching... (Ctrl+C to stop)\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[ORCHESTRATOR] Stopping all monitors...")
        observer.stop()
        observer.join()
        proc_monitor.stop()
        resource_monitor.stop()
        print("[ORCHESTRATOR] Shutdown complete.")


if __name__ == "__main__":
    main()
