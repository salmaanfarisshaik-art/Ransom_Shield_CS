"""
System Monitor (Phase 3)
------------------------
Collects host-level process and I/O metrics and pushes them periodically
to the FastAPI backend via POST /api/internal/sys_metrics.

Windows Sysmon integration:
    If the `win32evtlog` library is available AND Sysmon is installed and
    running, this module will read Sysmon event channel data.
    If either is missing, it falls back gracefully to psutil-only metrics
    and logs a clear startup message explaining the fallback.

    TODO (future enhancement): Add Linux auditd integration via the
    `audit` Python library or by tailing /var/log/audit/audit.log.
    The psutil fallback already works on Linux — auditd would add
    richer process-creation event data on that platform.

Security note:
    POST /api/internal/sys_metrics requires the same API token as other
    restricted endpoints (x-api-key header).  The token is read from
    backend/config.py so it never hard-codes credentials.
"""
import os
import sys
import time
import json
import platform
import urllib.request
import urllib.error

import psutil

from backend.config import SYS_MONITOR_CONFIG, API_AUTH_TOKEN

# ---------------------------------------------------------------------------
# Sysmon / win32evtlog optional import
# ---------------------------------------------------------------------------

_sysmon_available = False

if platform.system() == "Windows":
    try:
        import win32evtlog  # type: ignore
        _sysmon_available = True
        print("[SYS] win32evtlog imported successfully — will attempt Sysmon event reads.")
    except ImportError:
        print("[SYS] win32evtlog not available (pip install pywin32 to enable Sysmon integration).")
        print("[SYS] Falling back to psutil-only monitoring.")
else:
    print(f"[SYS] Non-Windows OS detected ({platform.system()}). "
          "Using psutil-only monitoring. "
          "Linux auditd integration is a planned future enhancement.")


# ---------------------------------------------------------------------------
# Sysmon reader (Windows-only, optional)
# ---------------------------------------------------------------------------

def _read_sysmon_events(max_events: int = 20) -> list:
    """
    Attempt to read recent Sysmon events from the Windows event log.
    Returns a list of dicts with basic event metadata.
    Returns an empty list if Sysmon is not installed or an error occurs.
    """
    if not _sysmon_available:
        return []

    events = []
    try:
        handle = win32evtlog.OpenEventLog(None, "Microsoft-Windows-Sysmon/Operational")
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        raw_events = win32evtlog.ReadEventLog(handle, flags, 0)
        for event in raw_events[:max_events]:
            events.append({
                "event_id": event.EventID & 0xFFFF,
                "time_generated": str(event.TimeGenerated),
                "source": str(event.SourceName),
            })
        win32evtlog.CloseEventLog(handle)
    except Exception as e:
        # Sysmon service may be installed but not running, or the channel name
        # may differ across Sysmon versions.  Log once and continue.
        print(f"[SYS] Sysmon event read failed: {e}")
        print("[SYS] Falling back to psutil-only for this poll cycle.")

    return events


# ---------------------------------------------------------------------------
# psutil metric collector
# ---------------------------------------------------------------------------

_last_disk_counters = None


def _collect_psutil_metrics() -> dict:
    """
    Collect system metrics via psutil.
    Returns a dict with cpu_percent, disk_write_mb_per_s, and memory_percent.
    """
    global _last_disk_counters

    cpu_percent = psutil.cpu_percent(interval=0.5)
    memory_percent = psutil.virtual_memory().percent

    # Calculate disk write speed since last poll
    current_counters = psutil.disk_io_counters()
    disk_write_mb = 0.0
    if _last_disk_counters is not None and current_counters is not None:
        bytes_written = current_counters.write_bytes - _last_disk_counters.write_bytes
        elapsed = SYS_MONITOR_CONFIG["poll_interval_seconds"]
        disk_write_mb = max(0.0, bytes_written / (1024 * 1024 * elapsed))
    _last_disk_counters = current_counters

    return {
        "cpu_percent": round(cpu_percent, 2),
        "disk_write_mb_per_s": round(disk_write_mb, 4),
        "memory_percent": round(memory_percent, 2),
    }


# ---------------------------------------------------------------------------
# API push
# ---------------------------------------------------------------------------

def _push_metrics(metrics: dict, fs_alert_count: int = 0):
    """
    POST collected metrics to the FastAPI backend's internal endpoint.
    Prints a clear error if the request fails so it never fails silently.
    """
    payload = {**metrics, "fs_alert_count": fs_alert_count}
    data = json.dumps(payload).encode("utf-8")

    req = urllib.request.Request(
        "http://127.0.0.1:8000/api/internal/sys_metrics",
        data=data,
        headers={
            "Content-Type": "application/json",
            "x-api-key": API_AUTH_TOKEN,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=3) as resp:
            status = resp.status
            if status != 200:
                print(f"[SYS] Unexpected API response: HTTP {status}")
    except urllib.error.URLError as e:
        print(f"[SYS] Failed to push metrics to API: {e.reason}. "
              "Is the FastAPI server running?")
    except Exception as e:
        print(f"[SYS] Unexpected error pushing metrics: {e}")


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def run(api_url: str = "http://127.0.0.1:8000"):
    """Start the continuous metrics collection loop."""
    interval = SYS_MONITOR_CONFIG["poll_interval_seconds"]
    sysmon_label = "psutil + Sysmon" if _sysmon_available else "psutil only"
    print(f"[SYS] System Monitor started (mode: {sysmon_label}, "
          f"poll interval: {interval}s)")

    if not _sysmon_available:
        print("[SYS] ACTION REQUIRED: To enable Sysmon integration, "
              "install Sysmon (sysmon64.exe -i sysmonconfig.xml) and "
              "run: pip install pywin32")

    while True:
        try:
            metrics = _collect_psutil_metrics()
            sysmon_events = _read_sysmon_events()

            if sysmon_events:
                print(f"[SYS] {len(sysmon_events)} Sysmon events read this cycle.")

            _push_metrics(metrics)

            print(f"[SYS] Metrics pushed — CPU: {metrics['cpu_percent']}% | "
                  f"Disk write: {metrics['disk_write_mb_per_s']} MB/s | "
                  f"RAM: {metrics['memory_percent']}%")

        except KeyboardInterrupt:
            print("\n[SYS] System Monitor stopped.")
            break
        except Exception as e:
            print(f"[SYS] Unhandled error in poll loop: {e}")

        time.sleep(interval)


if __name__ == "__main__":
    run()
