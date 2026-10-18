# RansomShield: Modular System Architecture & Forensic Evidence Pipeline

## Overview
RansomShield is a research-grade, evidence-driven, multi-signal ransomware detection, memory forensics, adaptive risk assessment, containment, and reporting platform.

```
+-----------------------------------------------------------------------------------+
|                                 SOC DASHBOARD (HTML5/WS)                          |
+-----------------------------------------------------------------------------------+
                                          ^ (WebSockets & REST)
                                          |
+-----------------------------------------------------------------------------------+
|                                  FASTAPI CORE ROUTER                              |
+-----------------------------------------------------------------------------------+
         |                        |                         |                      |
         v                        v                         v                      v
+------------------+    +------------------+    +------------------+    +-------------------+
| SECURITY & AUTH  |    | EVIDENCE STORE   |    | ADAPTIVE RISK    |    | CORRELATION GRAPH |
| - JWT Auth / RBAC|    | - SHA-256 Hashes |    | - Multi-Signal   |    | - Nodes & Edges   |
| - Decoy Boundary |    | - Chain-of-Custody|   | - 4-Tier Scoring |    | - Timeline Events |
+------------------+    +------------------+    +------------------+    +-------------------+
         |                        |                         |                      |
         v                        v                         v                      v
+-----------------------------------------------------------------------------------+
|                             DETECTION & FORENSIC ENGINES                          |
|  - Filesystem Shannon Entropy (watchdog)   - Host Telemetry & Sysmon              |
|  - Win32 C API MiniDump Memory Forensics   - YARA Signature Engine                |
|  - Volatility 3 Memory Plugin Pipeline      - IsolationForest ML Anomaly Engine    |
+-----------------------------------------------------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|                        SEQUENTIAL CONTAINMENT & RESPONSE                          |
|  Containment Trigger -> MiniDump -> SHA-256 -> YARA/Volatility -> Alert -> Kill  |
+-----------------------------------------------------------------------------------+
```

## Defensive Deception Boundary (Phase C)
- Tracks failed login attempts per IP.
- After 4 failed authentication attempts, redirects session to `session_type = DECOY` with an isolated decoy JWT token.
- Production API endpoints enforce `HTTP 403 Forbidden` against decoy tokens.
- Decoy database records and logs are isolated from production data.

## Sequential Dump-Before-Kill Pipeline (Phase T)
- Replaces legacy EDR process termination bugs where volatile memory evidence is lost.
- Sequence:
  1. Trigger Containment
  2. Win32 `MiniDumpWriteDump` Memory Acquisition
  3. Compute SHA-256 Digest
  4. YARA Signature Memory Scan
  5. Volatility 3 Memory Analysis
  6. Generate Alert & Evidence Entry
  7. Graceful Process Termination (`terminate()`)
  8. Hard Force Kill Fallback (`kill()`)
  9. Execution Verification (`pid_exists()`)
  10. Chain-of-Custody & Audit Log Entry

## Configurable Memory Retention Modes (Phase 43)
- `TEMPORARY`: Automatically deletes temporary dump file after scanning.
- `FORENSIC`: Retains dump file with SHA-256 hash and Chain of Custody.
- `RESEARCH`: Retains dump file, SHA-256 hash, metadata, and Volatility findings.

## Benchmark Baselines (B1–B5)
- **B1**: Process Only
- **B2**: Process + Sysmon
- **B3**: Process + Sysmon + YARA
- **B4**: Process + Sysmon + YARA + Memory
- **B5**: Full RansomShield (Process + Filesystem + Sysmon + Network + YARA + Memory + Volatility + ML + Anomaly + Correlation + Adaptive Risk)
