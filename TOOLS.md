# RansomShield Tools and Environment

This file documents the tools, their versions, and configuration details for the RansomShield project to ensure reproducible environments.

## Scope Exclusions
- The API endpoint `/api/agents/deploy` is explicitly out of scope for this backend implementation. The frontend deploy button may remain, but will not be backed by actual deployment logic at this time.

## Installed Tools

| Tool | Version | Description |
|---|---|---|
| Volatility 3 | (TBD) | Used for memory forensics and analysis of RAM dumps. |
| YARA | (TBD) | Used for pattern and signature detection in memory and files. |
| Sysmon | (TBD) | Windows System Monitor for advanced process and network tracking. *Requires manual driver installation via `sysmon64.exe -i sysmonconfig.xml`*. |
| Ghidra | (TBD) | Reverse engineering platform, used in headless mode for static analysis. |
| REMnux | (TBD) | Linux toolkit for malware analysis, used for safe dynamic detonation (of our synthetic samples). |
| AVML | (TBD) | Linux tool for memory acquisition. |
| auditd | (TBD) | Linux auditing framework for system behavior monitoring. |

## Notes
- All tools used in this project are open source and freely available.
- Real malware is strictly prohibited. Testing is performed exclusively with a benign python simulation script.

---

## Phase 3: System Monitor (`backend/modules/sys_monitor.py`)

Collects host-level metrics via `psutil` and pushes them every N seconds
(configurable in `backend/config.py` → `SYS_MONITOR_CONFIG`) to the API.

**Sysmon status:** `win32evtlog` integration is implemented but requires
manual setup. If `pywin32` is not installed or Sysmon is not running, the
script falls back to psutil-only and prints a clear `ACTION REQUIRED` message.
Sysmon remains a **manual setup step** — run:
```
sysmon64.exe -i sysmonconfig.xml
pip install pywin32
```

**Future enhancement:** Linux `auditd` integration (reading
`/var/log/audit/audit.log`) is planned but not yet implemented.
The psutil fallback works on Linux today.

---

## Phase 3: ML Anomaly Engine (`backend/modules/ml_anomaly.py`)

Uses `scikit-learn` `IsolationForest` to score system state against a
baseline of normal behaviour and flag anomalous patterns.

### ⚠️ SYNTHETIC DATA DISCLAIMER (patent-critical)

> The `IsolationForest` model is **calibrated exclusively on synthetically
> generated data** that approximates "normal" vs. "ransomware-like" behaviour
> (high CPU + high disk writes + elevated filesystem alert counts).
>
> **This is NOT production-validated training data.** The model has not been
> evaluated against real ransomware telemetry, real user workloads, or
> any external benchmark dataset. Any detection accuracy observed during
> simulator testing reflects synthetic conditions only and **must not be
> cited as a validated accuracy claim** in patent filings, academic papers,
> or product documentation without this qualification explicitly stated.

### Design decisions

- Training data includes deliberate Gaussian noise to prevent trivially-
  separable class boundaries (i.e., the model is NOT trained on perfectly
  extreme attack vs. perfectly quiet normal — see code comments).
- Thresholds and contamination parameters are in `ML_ANOMALY_CONFIG`
  in `backend/config.py` and can be tuned without code changes.
- The `AnomalyDetector` class is thread-safe: concurrent
  `POST /api/internal/sys_metrics` writes and `GET /api/risk-score`
  reads are protected by a `threading.Lock`.
- The model is calibrated once at FastAPI startup time on a daemon thread.

