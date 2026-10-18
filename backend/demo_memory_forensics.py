import os
import time
import subprocess
import sys
import backend.modules.memory_forensics as mem_for

def main():
    dump_dir = os.path.join(os.path.dirname(__file__), "data", "memory_dumps")
    os.makedirs(dump_dir, exist_ok=True)
    
    print("[*] Starting dummy process for YARA memory scanning...")
    dummy = subprocess.Popen([sys.executable, "backend/dummy_process.py"])
    time.sleep(1)
    
    print(f"\n[*] Contents of '{dump_dir}' BEFORE scan:")
    print("   ->", os.listdir(dump_dir) or "(Empty)")
    
    print(f"\n[*] Executing acquire_and_scan_memory({dummy.pid}) inside memory_forensics.py...")
    print("   (This will dump memory to disk, scan it with YARA, and clean it up immediately)")
    
    result = mem_for.acquire_and_scan_memory(dummy.pid)
    
    print(f"\n[*] Scan complete. Result: {result}")
    
    print(f"\n[*] Contents of '{dump_dir}' AFTER scan:")
    print("   ->", os.listdir(dump_dir) or "(Empty) - Cleanup successful!")
    
    dummy.kill()

if __name__ == "__main__":
    main()
