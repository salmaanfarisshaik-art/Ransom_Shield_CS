import psutil
import time
import subprocess
import logging

logger = logging.getLogger(__name__)

def kill_process(pid: int) -> dict:
    """
    Safely terminate a process by PID.
    Attempts a graceful terminate(), waits 3 seconds, then falls back to hard kill().
    """
    try:
        if not psutil.pid_exists(pid):
            return {
                "status": "success",
                "reason": "Process does not exist or was already terminated.",
                "mode": "real"
            }

        proc = psutil.Process(pid)
        
        # Graceful terminate
        proc.terminate()
        try:
            proc.wait(timeout=3.0)
            return {
                "status": "success",
                "reason": "Process terminated gracefully.",
                "mode": "real"
            }
        except psutil.TimeoutExpired:
            # Fallback to hard kill
            proc.kill()
            return {
                "status": "success",
                "reason": "Process killed forcefully after timeout.",
                "mode": "real"
            }

    except psutil.NoSuchProcess:
        return {
            "status": "success",
            "reason": "Process terminated before it could be killed.",
            "mode": "real"
        }
    except psutil.AccessDenied:
        return {
            "status": "failed",
            "reason": "Access Denied. Insufficient privileges to kill process.",
            "mode": "real"
        }
    except Exception as e:
        logger.error(f"Failed to kill process {pid}: {e}")
        return {
            "status": "failed",
            "reason": f"Unexpected error: {str(e)}",
            "mode": "real"
        }

def isolate_endpoint(endpoint_id: str, simulated: bool = True) -> dict:
    """
    Isolates the endpoint.
    By default, uses a safe simulated mode to avoid locking out the dev environment.
    """
    if simulated:
        return {
            "status": "success",
            "reason": f"Endpoint {endpoint_id} successfully isolated (Simulation mode)",
            "mode": "simulated"
        }
    else:
        # Real isolation using Windows netsh
        try:
            # Block all inbound traffic
            inbound_cmd = ["netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,blockoutbound"]
            subprocess.run(inbound_cmd, check=True, capture_output=True, text=True)
            
            return {
                "status": "success",
                "reason": f"Endpoint {endpoint_id} completely isolated via netsh firewall rules.",
                "mode": "real"
            }
        except subprocess.CalledProcessError as e:
            return {
                "status": "failed",
                "reason": f"netsh command failed: {e.stderr}",
                "mode": "real"
            }
        except Exception as e:
            return {
                "status": "failed",
                "reason": f"Unexpected error applying firewall rules: {str(e)}",
                "mode": "real"
            }
