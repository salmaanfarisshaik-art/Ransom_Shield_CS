import urllib.request
import json

API = "http://127.0.0.1:8000/api"
KEY = "changeme-in-production"

def get(path):
    req = urllib.request.Request(API + path, headers={"x-api-key": KEY})
    resp = urllib.request.urlopen(req, timeout=10)
    return json.loads(resp.read())

print("\n=== THREAT INTELLIGENCE CORRELATION ===")
ti = get("/threat-intel/correlate")
print("Alerts analyzed:", ti.get("alerts_analyzed"))
print("Top threat group:", ti.get("top_threat_group"))
print("Confidence:", ti.get("top_confidence_pct"), "%")
print("Groups matched:", ti.get("groups_matched"))
for c in ti.get("correlations", []):
    print(" -", c["group_name"], "| confidence:", c["confidence_pct"], "% | ransom demand: $" + str(c["avg_ransom_demand_usd"]))

print("\n=== SECTOR IMPACT ASSESSMENT ===")
si = get("/sector-impact")
for sid, v in si.get("assessment", {}).items():
    print(f"  [{v['severity']:8s}] {v['sector_name']:35s} | impact={v['impact_score']:5.1f} | est. cost=${v['estimated_cost_usd']:,}")

print("\n=== INCIDENT COMMAND CENTER STATUS ===")
cc = get("/command-center/status")
print("Incident Status:", cc.get("incident_status"))
print("Risk Score:", cc.get("risk_score"))
print("Total Alerts:", cc["alert_summary"]["total"])
print("Critical Alerts:", cc["alert_summary"]["critical"])
print("Containment Actions:", cc["containment_summary"]["total_actions"])
print("Kali Lab Sessions:", len(cc.get("kali_lab_sessions", [])))
print("Top Threat:", cc["threat_intel"]["top_group"], "| Confidence:", cc["threat_intel"]["confidence_pct"], "%")
print("\nSector Top 3:")
for s in cc.get("sector_impact_top3", []):
    print(f"  {s['severity']:8s} | {s['sector']}")
