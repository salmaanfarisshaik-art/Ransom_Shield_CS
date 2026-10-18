import time

# This string is explicitly hunted by our YARA rule
_SIMULATION_SIGNATURE = b"RANSOM_SIMULATION_ACTIVE"

if __name__ == "__main__":
    print(f"Dummy process running with signature: {_SIMULATION_SIGNATURE}")
    print("Will sleep for 600s...")
    try:
        time.sleep(600)
    finally:
        print("Dummy process exiting safely.")
