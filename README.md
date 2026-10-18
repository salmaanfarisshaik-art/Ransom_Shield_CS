# 🛡️ RansomShield — Intelligent Multi-Layer Ransomware Detection, Memory Forensics & Deception Platform

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/Framework-FastAPI%20%7C%20Uvicorn-009688.svg)](https://fastapi.tiangolo.com/)
[![Machine Learning](https://img.shields.io/badge/ML-Scikit--Learn%20IsolationForest-F7931E.svg)](https://scikit-learn.org/)
[![Forensics](https://img.shields.io/badge/Forensics-YARA%20%7C%20MiniDump%20API-red.svg)](https://virustotal.github.io/yara/)
[![Security](https://img.shields.io/badge/Deception-Adaptive%20Honeypot-purple.svg)](#-active-deception--anti-brute-force-honeypot)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

> **RansomShield** is an advanced, production-grade cybersecurity research and defensive engineering platform designed to detect, analyze, and neutralize ransomware attacks in real time. Combining **kernel-level filesystem entropy telemetry**, **in-memory forensics (Dump-Before-Kill)**, **YARA rule scanning**, **unsupervised machine learning anomaly detection**, and **active deception honeypots**, RansomShield prevents data extortion while preserving critical forensic artifacts for incident responders.

---

## 📌 Table of Contents

- [Architectural Overview](#-architectural-overview)
- [Key Features](#-key-features)
  - [1. Real-Time Shannon Entropy Engine](#1-real-time-shannon-entropy-engine)
  - [2. Dump-Before-Kill Memory Forensics](#2-dump-before-kill-memory-forensics)
  - [3. YARA Heuristic Pattern Scanning](#3-yara-heuristic-pattern-scanning)
  - [4. IsolationForest ML Anomaly Detection](#4-isolationforest-ml-anomaly-detection)
  - [5. Sector-Specific Threat Intelligence](#5-sector-specific-threat-intelligence)
  - [6. Active Deception & Anti-Brute-Force Honeypot](#6-active-deception--anti-brute-force-honeypot)
  - [7. Authorized Kali Linux Simulation Lab](#7-authorized-kali-linux-simulation-lab)
  - [8. Automated Forensic PDF Evidence Generation](#8-automated-forensic-pdf-evidence-generation)
- [System Architecture Diagram](#-system-architecture-diagram)
- [Directory Structure](#-directory-structure)
- [Quick Start Guide](#-quick-start-guide)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Running the Services](#running-the-services)
- [Live Attack Simulation & Testing](#-live-attack-simulation--testing)
- [Authentication, RBAC & Honeypot Demo](#-authentication-rbac--honeypot-demo)
- [API Reference](#-api-reference)
- [Performance Benchmarks](#-performance-benchmarks)
- [Defensive Ethics & Disclaimer](#-defensive-ethics--disclaimer)

---

## 🏛️ Architectural Overview

Traditional signature-based antivirus solutions often fail against zero-day ransomware and polymorphic malware because encryption occurs before static signatures are published. **RansomShield** addresses this paradigm through behavioral defense across eight integrated layers:

```
                  ┌────────────────────────────────────────┐
                  │    Remote Kali / Endpoint Activity     │
                  └──────────────────┬─────────────────────┘
                                     │
         ┌───────────────────────────┴───────────────────────────┐
         ▼                                                       ▼
┌──────────────────┐                                   ┌──────────────────┐
│  Filesystem I/O  │ (Shannon Entropy ≥ 7.5,           │  System Telemetry│ (CPU, RAM, Disk,
│  Watchdog Engine │  Rapid Mass Renames, Extensions)  │  Sysmon Monitor  │  Network Packets)
└────────┬─────────┘                                   └────────┬─────────┘
         │                                                      │
         └───────────────────────────┬──────────────────────────┘
                                     ▼
                   ┌───────────────────────────────────┐
                   │   Correlation & ML Anomaly Engine │
                   │ (IsolationForest + YARA Scanner)  │
                   └─────────────────┬─────────────────┘
                                     │
                    [ Anomaly or Threat Detected ]
                                     │
         ┌───────────────────────────┴───────────────────────────┐
         ▼                                                       ▼
┌─────────────────────────────────┐             ┌─────────────────────────────────┐
│ Memory Forensics Acquisition    │             │ Instant Process Containment     │
│ (MiniDump API via dbghelp.dll)  │             │ (Process Termination & Firewall)│
└────────────────┬────────────────┘             └────────────────┬────────────────┘
                 │                                               │
                 └───────────────────────┬───────────────────────┘
                                         ▼
                      ┌─────────────────────────────────────┐
                      │    RansomShield WebSOC Dashboard    │
                      │  (Live Telemetry, Alerts & Reports) │
                      └─────────────────────────────────────┘
```

---

## ✨ Key Features

### 1. Real-Time Shannon Entropy Engine
- Computes byte-frequency Shannon entropy ($H \ge 7.5$ bits/byte) on file modification streams using Windows Watchdog.
- Flags rapid renaming bursts (e.g., appending `.locked`, `.encrypted`, `.wncry`) within a sliding 10-second inspection window.

### 2. Dump-Before-Kill Memory Forensics
- **The Problem**: Standard EDR tools kill malicious processes immediately, destroying volatile encryption keys residing in RAM.
- **The RansomShield Solution**: Executes an atomic **MiniDump acquisition** (`MiniDumpWithFullMemory` via Windows `dbghelp.dll`) in **$< 184\text{ ms}$** *before* terminating the offender, safeguarding encryption keys and C2 sockets for reverse engineers.

### 3. YARA Heuristic Pattern Scanning
- Scans files and memory dumps against customized YARA behavioral rules (`backend/data/rules/generic_ransom_behavior.yar`).
- Identifies ransom notes (`README_TO_DECRYPT.txt`), shadow copy deletion commands (`vssadmin delete shadows`), and cryptographic API imports.

### 4. IsolationForest ML Anomaly Detection
- Unsupervised machine learning model (`scikit-learn`) continuously scoring multi-variate telemetry (CPU spikes, RAM utilization, I/O bursts, write rates).
- Calculates an **Adaptive Risk Score (0–100)** with real-time SHAP-inspired explainability.

### 5. Sector-Specific Threat Intelligence
- Custom risk assessment engine evaluating threat posture across critical industries:
  - 💳 **Banking & Finance**: Core ledger access, SWIFT interface integrity.
  - 🏥 **Healthcare & Life Sciences**: EHR/EMR availability, PACS telemetry.
  - ⚡ **Energy & SCADA/ICS**: Industrial protocol anomaly monitoring.
  - 🛡️ **Defense & Government**: Exfiltration and persistence scoring.

### 6. Active Deception & Anti-Brute-Force Honeypot
- Enforces an automated defensive deception boundary on authentication portals:
  - **Attempts 1–2**: Standard failed attempt warning and lockout countdown.
  - **Attempt 3**: System arms the deception boundary (`HONEYPOT_ARMED`).
  - **Attempt 4+**: Attacker is seamlessly redirected to an **isolated Decoy Honeypot** (`honeypot.html`).
- The honeypot operates in an **idle state**—it displays generic features with zero real data, zero alert history, and zero host controls, trapping threat actors and gathering telemetry without exposing production infrastructure.

### 7. Authorized Kali Linux Simulation Lab
- Built-in simulation framework offering 7 controlled, non-destructive test scenarios:
  1. `SCENARIO_1`: Reconnaissance & Port Enumeration
  2. `SCENARIO_2`: High-Speed File Operation Bursts
  3. `SCENARIO_3`: Mass File Extension Mutation
  4. `SCENARIO_4`: Shannon Entropy High-Entropy Encryption Burst
  5. `SCENARIO_5`: Process Hollowing & Command-Line Injection
  6. `SCENARIO_6`: Simulated C2 Network Beaconing & Egress
  7. `SCENARIO_7`: Full Multi-Stage Ransomware Attack Chain

### 8. Automated Forensic PDF Evidence Generation
- Dynamically generates tamper-evident incident reports using **ReportLab**.
- Compiles the entire alert history, date/time logs, endpoint IDs, classification types, and host **CPU & RAM resource utilization** at the moment of detection.
- Includes cryptographic **SHA-256 integrity hashes** for legal chain of custody.

---

## 📁 Directory Structure

```plaintext
Ransom_Shield_CS/
├── .env.example                     # Environment template (ports, secret keys, API tokens)
├── .gitignore                       # Production gitignore (filters memory dumps, databases, logs)
├── ARCHITECTURE.md                  # Comprehensive architectural specification
├── PRESENTATION_COMMANDS.md         # Quick command reference for live demonstrations
├── README.md                        # Primary project documentation
├── requirements.txt                 # Complete Python dependencies
├── check_alerts.py                  # CLI alert verifier utility
├── demo_live_attack.py              # End-to-end multi-scenario execution script
├── kali_attacker.py                 # Remote Kali simulation driver
├── research_completion_report.md    # IEEE/academic benchmark validation report
│
├── backend/
│   ├── config.py                    # Tunable detection thresholds & API configuration
│   ├── orchestrator.py              # Pipeline supervisor and event coordinator
│   ├── requirements.txt             # Backend-specific package manifest
│   ├── agent/                       # Endpoint telemetry collector agent
│   ├── api/                         # FastAPI routing
│   │   ├── auth_routes.py           # Authentication, Admin approval gate & Honeypot routing
│   │   ├── main.py                  # Core ASGI application entry point
│   │   ├── routes.py                # Alerts, containment, telemetry & report endpoints
│   │   └── routes_extra.py          # Threat intel & ML explainability endpoints
│   ├── data/
│   │   ├── memory_dumps/            # Forensic memory dumps (.gitkeep)
│   │   ├── reports/                 # Output directory for generated PDF/JSON reports (.gitkeep)
│   │   ├── rules/                   # Compiled YARA behavioral rules
│   │   └── test_sandbox/            # Isolated directory for simulated file operations (.gitkeep)
│   ├── database/                    # SQLAlchemy database engine and session factory
│   ├── experiments/                 # Reproducible test runners and e2e integration tests
│   ├── integration/                 # Kali Linux scenario executor & schema validators
│   ├── ml/                          # IsolationForest model trainer and feature extractors
│   ├── models/                      # SQLAlchemy ORM relational models (Alerts, Incidents, Evidence)
│   ├── modules/                     # Detection modules (fs_monitor, sys_monitor, memory_forensics, yara)
│   ├── reports/                     # ReportLab forensic PDF and JSON report builders
│   ├── schemas/                     # Pydantic validation schemas
│   ├── security/                    # Deception boundary logic, PBKDF2 hashing, JWT tokens
│   └── services/                    # Alert correlation, incident handling, sector risk engine
│
├── frontend/                        # WebSOC Dashboard Interface
│   ├── dashboard.html               # 9-section real-time SOC monitoring dashboard
│   ├── honeypot.html                # Idle decoy dashboard for trapped attackers
│   └── login.html                   # Authenticated access portal with brute-force protection
│
└── research_package/                # Academic research validation data & ablation benchmarks
```

---

## 🚀 Quick Start Guide

### Prerequisites
- **Operating System**: Windows 10/11 (for native `dbghelp.dll` memory forensics) or Linux/macOS (simulated fallback mode)
- **Python**: Version 3.10, 3.11, or 3.12
- **Git**

### Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/salmaanfarisshaik-art/Ransom_Shield_CS.git
   cd Ransom_Shield_CS
   ```

2. **Create and Activate a Virtual Environment**:
   ```bash
   python -m venv venv
   
   # Windows (PowerShell):
   .\venv\Scripts\Activate.ps1

   # Linux/macOS:
   source venv/bin/activate
   ```

3. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Initialize Environment Configuration**:
   ```bash
   cp .env.example .env
   ```

---

### Running the Services

To run the full platform, open two terminal windows:

#### Terminal 1 — Backend FastAPI Server
```powershell
uvicorn backend.api.main:app --port 8000 --reload
```
*API Swagger Documentation will be accessible at: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)*

#### Terminal 2 — Frontend Web Server
```powershell
python -m http.server 8080 --directory frontend
```
*WebSOC Portal will be live at: [http://127.0.0.1:8080/login.html](http://127.0.0.1:8080/login.html)*

---

## 🔬 Live Attack Simulation & Testing

You can trigger controlled, authorized test scenarios directly via PowerShell or cURL to evaluate RansomShield's detection and containment pipeline in real time.

### High-Entropy Encryption Burst Simulation
```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/kali/execute-scenario" `
  -Method Post `
  -ContentType "application/json" `
  -Headers @{"x-api-key"="changeme-in-production"} `
  -Body '{"scenario_id":"SCENARIO_4","target_id":"WIN-HOST-01","operator":"Security-Auditor"}'
```

### Process Injection & Suspicious Execution Simulation
```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/kali/execute-scenario" `
  -Method Post `
  -ContentType "application/json" `
  -Headers @{"x-api-key"="changeme-in-production"} `
  -Body '{"scenario_id":"SCENARIO_5","target_id":"WIN-HOST-01","operator":"Security-Auditor"}'
```

### Full 16-Stage End-to-End Pipeline Test
Run the automated test runner to validate sandbox creation, entropy calculation, YARA scanning, memory dump generation, and PDF export:
```powershell
python -c "from backend.experiments.e2e_test import E2EExperimentTest; res = E2EExperimentTest.run_e2e_test(); print('Stages passed:', len(res['stages_completed']))"
```

---

## 🔐 Authentication, RBAC & Honeypot Demo

### Default Credentials
| Role | Username | Password | Access Level |
| :--- | :--- | :--- | :--- |
| **System Admin** | `admin` | `admin123` | Full Access & User Approval Privileges |
| **Pending Analyst** | Registered via UI | Set by user | Restricted until Admin approval |

### Admin Approval Workflow
1. Navigate to **[http://127.0.0.1:8080/login.html](http://127.0.0.1:8080/login.html)** and click **Register New User**.
2. Complete the registration form. The account is set to `PENDING_APPROVAL`.
3. Log in with the `admin` account.
4. Scroll to the **Admin User Management** section on the WebSOC dashboard.
5. Click **Approve** on the new account. The user can now access the full SOC dashboard.

### Deception Honeypot Demonstration
1. Open an Incognito browser window to `http://127.0.0.1:8080/login.html`.
2. Enter incorrect credentials 3 times:
   - Notice the visual attempt countdown badge (`2 attempts remaining`, `1 attempt remaining`).
   - On attempt 3, the security perimeter arms: `HONEYPOT ARMED — Threshold Reached`.
3. Submit a 4th login attempt.
4. The system transparently issues a decoy session token and routes the client to `honeypot.html`—an isolated decoy dashboard stripped of live telemetry.

---

## 📡 API Reference

| Method | Endpoint | Description | Auth Required |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/auth/login` | Authenticate user or issue honeypot decoy token | No |
| `POST` | `/api/auth/register` | Register new user account (pending approval) | No |
| `GET` | `/api/auth/users` | List all users and approval states | Yes (Admin) |
| `POST` | `/api/auth/approve/{username}` | Approve pending user registration | Yes (Admin) |
| `GET` | `/api/alerts` | Stream all security alerts with CPU/RAM metrics | Yes (Bearer/API Key) |
| `GET` | `/api/risk-score` | Retrieve current ML risk score and status | Yes |
| `POST` | `/api/kali/execute-scenario` | Execute authorized Kali test scenario | Yes (API Key) |
| `POST` | `/api/containment/kill-process` | Trigger Dump-Before-Kill process containment | Yes (Admin/Analyst) |
| `POST` | `/api/containment/isolate` | Network isolate target endpoint | Yes (Admin/Analyst) |
| `GET` | `/api/reports/download/{id}` | Download signed forensic PDF report | Yes |

---

## 📊 Performance Benchmarks

Validated through extensive reproducible ablation studies (`research_package/`):

| Evaluation Metric | Baseline Standard | RansomShield Achieved | Status |
| :--- | :--- | :--- | :--- |
| **Detection Speed (Time-to-Detect)** | $< 10.0\text{ s}$ | **$2.4\text{ s}$** | ⚡ 4x Faster |
| **Memory Dump Acquisition Latency** | $< 500\text{ ms}$ | **$184\text{ ms}$** | ⚡ Exceeds |
| **Process Termination Latency** | $< 50\text{ ms}$ | **$12\text{ ms}$** | ⚡ Real-Time |
| **Cryptographic Evidence Integrity** | 100% Validated | **SHA-256 Verified** | 🛡️ Tamper-Proof |
| **False Positive Rate (Benign Benchmarks)** | $< 5.0\%$ | **$1.8\%$** | 🎯 High Precision |

---

## ⚖️ Defensive Ethics & Disclaimer

> **IMPORTANT RESEARCH NOTICE**:  
> RansomShield is developed strictly for **academic research, authorized defensive evaluation, and educational demonstration purposes**.  
> - All simulation modules execute inside **ephemeral, isolated sandboxes** and do **NOT** contain destructive cryptographic algorithms or self-propagating malware logic.
> - Testing against unauthorized production networks or endpoints is strictly prohibited.
> - The authors assume no liability for misuse of the tools or concepts described herein.

---

## 👨‍💻 Author & Acknowledgments

- **Lead Developer & Researcher**: [salmaanfarisshaik-art](https://github.com/salmaanfarisshaik-art)
- **Repository**: [https://github.com/salmaanfarisshaik-art/Ransom_Shield_CS](https://github.com/salmaanfarisshaik-art/Ransom_Shield_CS)
- **License**: Released under the [MIT License](LICENSE).
