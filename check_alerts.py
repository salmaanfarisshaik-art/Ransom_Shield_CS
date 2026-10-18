import urllib.request
import json

API_KEY = "changeme-in-production"
API_BASE = "http://127.0.0.1:8000/api"

req = urllib.request.Request(
    API_BASE + "/alerts",
    headers={"x-api-key": API_KEY}
)
resp = urllib.request.urlopen(req, timeout=5)
alerts = json.loads(resp.read())
print("Total alerts in dashboard:", len(alerts))
for a in alerts:
    atype = a.get("alert_type", "?")
    msg = a.get("message", "")[:70]
    print("  [" + atype + "] " + msg)
