"""
Filesystem Behavioral Monitor
-----------------------------
Monitors a target directory for high-entropy file writes and rapid file renames.
"""
import os
import time
import math
from collections import deque
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from backend.config import FS_MONITOR_CONFIG

def calculate_shannon_entropy(filepath):
    """Calculate the Shannon entropy of a file's contents."""
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
            
        if not data:
            return 0.0
            
        entropy = 0
        length = len(data)
        
        # Count byte frequencies
        frequencies = [0] * 256
        for byte in data:
            frequencies[byte] += 1
            
        for count in frequencies:
            if count > 0:
                prob = count / length
                entropy -= prob * math.log2(prob)
                
        return entropy
    except Exception as e:
        print(f"Error calculating entropy for {filepath}: {e}")
        return 0.0

class StandardFileEntropyEngine:
    """Calculates Shannon Entropy for byte sequences or file contents."""
    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        length = len(data)
        frequencies = [0] * 256
        for byte in data:
            frequencies[byte] += 1
        entropy = 0.0
        for count in frequencies:
            if count > 0:
                prob = count / length
                entropy -= prob * math.log2(prob)
        return entropy

    @staticmethod
    def calculate_file_entropy(filepath: str) -> float:
        return calculate_shannon_entropy(filepath)


class RansomwareBehaviorHandler(FileSystemEventHandler):
    def __init__(self, alert_callback, debug=False):
        self.alert_callback = alert_callback
        self.debug = debug
        self.rename_events = deque() # Store (timestamp, src, dest)
        self.entropy_events = deque()
        
    def _cleanup_old_events(self, current_time):
        window = FS_MONITOR_CONFIG['time_window_seconds']
        while self.rename_events and current_time - self.rename_events[0][0] > window:
            self.rename_events.popleft()
        while self.entropy_events and current_time - self.entropy_events[0][0] > window:
            self.entropy_events.popleft()

    def on_any_event(self, event):
        if self.debug:
            print(f"[DEBUG ANY] {event}")

    def on_created(self, event):
        if self.debug:
            print(f"[DEBUG RAW] on_created fired for: {event.src_path}")
        if event.is_directory:
            return

    def on_deleted(self, event):
        if self.debug:
            print(f"[DEBUG RAW] on_deleted fired for: {event.src_path}")
        if event.is_directory:
            return

    def on_moved(self, event):
        if self.debug:
            print(f"[DEBUG RAW] on_moved fired for: {event.src_path} -> {event.dest_path}")
        if event.is_directory:
            return

        if str(event.dest_path).endswith('.locked'):
            self.alert_callback("SUSPICIOUS_RENAME", f"Suspicious rename pattern detected: {event.src_path} -> {event.dest_path}")
            
        current_time = time.time()
        self.rename_events.append((current_time, event.src_path, event.dest_path))
        self._cleanup_old_events(current_time)
        
        if len(self.rename_events) >= FS_MONITOR_CONFIG['rename_threshold']:
            self.alert_callback("RAPID_RENAME_DETECTED", f"Detected {len(self.rename_events)} renames in {FS_MONITOR_CONFIG['time_window_seconds']}s")
            self.rename_events.clear() # Reset after alert

    def on_modified(self, event):
        if self.debug:
            print(f"[DEBUG RAW] on_modified fired for: {event.src_path}")
        if event.is_directory:
            return

        # Add slight delay to ensure file write is complete before reading
        time.sleep(0.05)
        entropy = calculate_shannon_entropy(event.src_path)
        
        if entropy >= FS_MONITOR_CONFIG['high_entropy_threshold']:
            self.alert_callback("HIGH_ENTROPY_WRITE", f"High-entropy write detected: {event.src_path} (entropy: {entropy:.2f})")
            current_time = time.time()
            self.entropy_events.append((current_time, event.src_path, entropy))
            self._cleanup_old_events(current_time)
            
            if len(self.entropy_events) >= FS_MONITOR_CONFIG['entropy_write_threshold']:
                self.alert_callback("HIGH_ENTROPY_WRITES_DETECTED", f"Detected {len(self.entropy_events)} high entropy writes in {FS_MONITOR_CONFIG['time_window_seconds']}s")
                self.entropy_events.clear()

class FSMonitor:
    def __init__(self, target_dir, alert_callback, debug=False):
        self.target_dir = target_dir
        self.alert_callback = alert_callback
        self.debug = debug
        self.observer = None
        
    def start(self):
        abs_target = os.path.abspath(self.target_dir)
        print(f"Monitoring started, watching {abs_target}... (Debug: {self.debug})")
        event_handler = RansomwareBehaviorHandler(self.alert_callback, self.debug)
        self.observer = Observer()
        self.observer.schedule(event_handler, abs_target, recursive=True)
        self.observer.start()
        
    def stop(self):
        if self.observer:
            self.observer.stop()
            self.observer.join()
            print("[*] FS Monitor stopped.")

if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="Filesystem Behavioral Monitor")
    parser.add_argument("--sandbox", required=True, help="Directory to monitor")
    parser.add_argument("--debug", action="store_true", help="Enable raw event debug prints")
    args = parser.parse_args()

    if not os.path.exists(args.sandbox):
        print(f"Error: Directory {args.sandbox} does not exist.")
        sys.exit(1)

    def alert_printer(alert_type, message):
        print(f"[*] LIVE ALERT: {alert_type} | {message}")
        try:
            import urllib.request
            import json
            from backend.config import API_AUTH_TOKEN
            
            req = urllib.request.Request(
                "http://127.0.0.1:8000/api/internal/alert",
                data=json.dumps({"alert_type": alert_type, "message": message}).encode('utf-8'),
                headers={"Content-Type": "application/json", "x-api-key": API_AUTH_TOKEN},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=2) as response:
                pass
        except Exception as e:
            print(f"Failed to push alert to API: {e}")

    monitor = FSMonitor(args.sandbox, alert_printer, debug=args.debug)
    monitor.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping monitor...")
    finally:
        monitor.stop()
