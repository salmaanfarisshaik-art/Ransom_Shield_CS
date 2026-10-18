import sys
import time
import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class LoggingEventHandler(FileSystemEventHandler):
    def on_any_event(self, event):
        print(f"EVENT DETECTED: {event}")

if __name__ == "__main__":
    target_dir = os.path.abspath(os.path.join("backend", "data", "test_sandbox"))
    
    if not os.path.exists(target_dir):
        print(f"Directory not found: {target_dir}")
        sys.exit(1)
        
    print(f"Starting minimal watchdog test on: {target_dir}")
    
    event_handler = LoggingEventHandler()
    observer = Observer()
    observer.schedule(event_handler, target_dir, recursive=True)
    observer.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping...")
    finally:
        observer.stop()
        observer.join()
