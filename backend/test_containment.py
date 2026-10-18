import subprocess
import requests
import time
import sys

API_BASE = "http://127.0.0.1:8000/api"
API_KEY = "changeme-in-production"
HEADERS = {"x-api-key": API_KEY}

def main():
    print("[*] Starting dummy process for testing...")
    # Spawn dummy process in the background
    dummy_proc = subprocess.Popen([sys.executable, "backend/dummy_process.py"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    try:
        pid = dummy_proc.pid
        print(f"[*] Dummy process spawned with PID {pid}. Waiting 2s for it to settle...")
        time.sleep(2)
        
        # Test 1: Kill Process API
        print(f"\n[*] Testing POST /api/process/{pid}/kill...")
        res = requests.post(f"{API_BASE}/process/{pid}/kill", headers=HEADERS)
        print(f"Response ({res.status_code}): {res.json()}")
        
        # Test 2: Isolate Endpoint API
        print(f"\n[*] Testing POST /api/endpoint/local-host-01/isolate...")
        res = requests.post(f"{API_BASE}/endpoint/local-host-01/isolate", headers=HEADERS)
        print(f"Response ({res.status_code}): {res.json()}")
        
        # Test 3: Verify Containment Log
        print(f"\n[*] Fetching GET /api/containment-log...")
        res = requests.get(f"{API_BASE}/containment-log")
        log = res.json()
        print(f"Containment Log Entries (Last 2):")
        for entry in log[-2:]:
            print(f"  - [{entry['mode'].upper()}] {entry['action']} on {entry['endpoint']} -> {entry['status']}: {entry['trigger_reason']}")
            
    except Exception as e:
        print(f"[!] Test failed with exception: {e}")
    finally:
        # Guarantee cleanup of the dummy process just in case the API call failed
        if dummy_proc.poll() is None:
            print(f"\n[!] Dummy process {dummy_proc.pid} is STILL running! Force killing it via psutil...")
            import psutil
            try:
                psutil.Process(dummy_proc.pid).kill()
                print("[*] Successfully force-killed stranded dummy process.")
            except Exception as e:
                print(f"[!] Failed to force-kill! {e}")
        else:
            print(f"\n[*] Verified: Dummy process {dummy_proc.pid} is no longer running. Cleanup successful.")

if __name__ == "__main__":
    main()
