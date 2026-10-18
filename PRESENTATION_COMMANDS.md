# ============================================================
#   RANSOMSHIELD — PRESENTATION COMMAND GUIDE
# ============================================================

## STEP 0 — OPEN TERMINAL WINDOWS SIDE BY SIDE

# Navigate to project root:
cd Ransom_Shield_CS

# ────────────────────────────────────────────────────────────
# TERMINAL 1  |  Backend API Server
# ────────────────────────────────────────────────────────────
uvicorn backend.api.main:app --port 8000

# ────────────────────────────────────────────────────────────
# TERMINAL 2  |  Frontend Dashboard Server
# ────────────────────────────────────────────────────────────
python -m http.server 8080

# ────────────────────────────────────────────────────────────
# TERMINAL 3  |  Filesystem + System Monitors (optional, shows live telemetry)
# ────────────────────────────────────────────────────────────
python -m backend.modules.fs_monitor --sandbox backend\data\test_sandbox
# (open 4th terminal for sys_monitor)

# ────────────────────────────────────────────────────────────
# TERMINAL 4  |  System Resource Monitor (CPU, RAM, Disk → ML Engine)
# ────────────────────────────────────────────────────────────
python -m backend.modules.sys_monitor

# ────────────────────────────────────────────────────────────
# BROWSER  |  Open Dashboard
# ────────────────────────────────────────────────────────────
# Navigate to: http://127.0.0.1:8080/dashboard.html


## ════════════════════════════════════════════════════════════
##   DEMO 1  |  CONTROLLED SIMULATION (Windows Local)
##   "This runs a full ransomware attack on this machine"
## ════════════════════════════════════════════════════════════

# In a NEW terminal:
python demo_live_attack.py --auto

# What it does:
#  Phase 1 → Creates 12 victim files (invoice, patient data, SCADA config...)
#  Phase 2 → Overwrites with os.urandom() — entropy 7.95 (real AES-256 level)
#  Phase 3 → Renames ALL files to .locked  (mass rename attack)
#  Phase 4 → Drops README_TO_DECRYPT.txt  (ransom note — YARA matched!)
#  Phase 5 → Shadow copy deletion pattern (anti-recovery YARA match)
#  Phase 6 → ML Anomaly Engine → Risk Score 90/100 → ANOMALY
#  Phase 7 → Process termination + Endpoint isolation
#  Phase 8 → Forensic PDF auto-generated with SHA-256


## ════════════════════════════════════════════════════════════
##   DEMO 2  |  KALI LINUX ATTACK (Simulated Red Team)
##   "This is the Kali Linux attacker sending attacks to Windows"
## ════════════════════════════════════════════════════════════

# Run from this Windows machine (simulates Kali):
python kali_attacker.py --auto

# OR run specific scenarios:
python kali_attacker.py --auto --scenario SCENARIO_1   # LOW  — benign baseline
python kali_attacker.py --auto --scenario SCENARIO_3   # HIGH — rename burst
python kali_attacker.py --auto --scenario SCENARIO_4   # HIGH — encryption writes
python kali_attacker.py --auto --scenario SCENARIO_7   # CRITICAL — full attack

# OR just local sandbox (show files being encrypted on screen):
python kali_attacker.py --local-only

# IF using REAL Kali Linux on same network:
# python3 kali_attacker.py --api http://<THIS_MACHINE_IP>:8000 --scenario SCENARIO_7


## ════════════════════════════════════════════════════════════
##   DEMO 3  |  INDIVIDUAL DETECTORS (show each module works)
## ════════════════════════════════════════════════════════════

# Filesystem Monitor + Simulator (triggers real file events):
python -m backend.modules.fs_monitor --sandbox backend\data\test_sandbox
# (then in another terminal:)
python -m backend.simulation.simulator --sandbox backend\data\test_sandbox

# System Monitor (ML-ready CPU/Disk metrics):
python -m backend.modules.sys_monitor

# Memory Forensics test:
python -m backend.modules.memory_forensics


## ════════════════════════════════════════════════════════════
##   DEMO 4  |  API ENDPOINTS (show to faculty — live JSON)
##   Open in browser or paste in PowerShell
## ════════════════════════════════════════════════════════════

# Live Alerts:
Invoke-WebRequest -Uri "http://127.0.0.1:8000/api/alerts" -Headers @{"x-api-key"="changeme-in-production"} | ConvertFrom-Json | ConvertTo-Json

# Risk Score:
Invoke-WebRequest -Uri "http://127.0.0.1:8000/api/risk-score" -Headers @{"x-api-key"="changeme-in-production"} | ConvertFrom-Json | ConvertTo-Json

# Threat Intel — which ransomware group matches our attack?
Invoke-WebRequest -Uri "http://127.0.0.1:8000/api/threat-intel/correlate" -Headers @{"x-api-key"="changeme-in-production"} | ConvertFrom-Json | ConvertTo-Json

# Sector Impact — which industries are most at risk?
Invoke-WebRequest -Uri "http://127.0.0.1:8000/api/sector-impact" -Headers @{"x-api-key"="changeme-in-production"} | ConvertFrom-Json | ConvertTo-Json

# All Kali Scenarios:
Invoke-WebRequest -Uri "http://127.0.0.1:8000/api/lab/kali/scenarios" -Headers @{"x-api-key"="changeme-in-production"} | ConvertFrom-Json | ConvertTo-Json

# Generate Forensic Report:
Invoke-WebRequest -Uri "http://127.0.0.1:8000/api/reports/quick-generate" -Method POST -Headers @{"x-api-key"="changeme-in-production";"Content-Type"="application/json"} -Body "{}" | ConvertFrom-Json | ConvertTo-Json

# Swagger API Docs (show all 40+ endpoints):
# http://127.0.0.1:8000/docs


## ════════════════════════════════════════════════════════════
##   QUICK DEMO FLOW FOR 5-MINUTE FACULTY PRESENTATION
## ════════════════════════════════════════════════════════════

# 1. Open browser → http://127.0.0.1:8080/dashboard.html
# 2. Run: python demo_live_attack.py --auto
# 3. Point to "Live Alerts" tab as alerts flood in
# 4. Show "Threat Intel" → "LockBit 3.0 — 100% confidence"
# 5. Show "Sector Impact" → "Critical Infrastructure — CRITICAL — $3.07M"
# 6. Run: python kali_attacker.py --auto
# 7. Show forensic PDF in backend/data/reports/
# 8. Open: http://127.0.0.1:8000/docs  → show 40+ API endpoints
