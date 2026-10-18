"""
RansomShield Process Identity Validator (Section 3)
Prevents PID-reuse attacks by comparing recorded creation_time against
the LIVE process creation time before any containment action.

Results:
  IDENTITY_VALID        - PID matches recorded instance
  IDENTITY_MISMATCH     - PID was reused by a different process
  PROCESS_NOT_FOUND     - PID no longer exists
  VALIDATION_FAILED     - Unexpected error during validation
"""
import psutil
import logging
from datetime import datetime
from typing import Optional, Tuple

logger = logging.getLogger(__name__)

IDENTITY_VALID = "IDENTITY_VALID"
IDENTITY_MISMATCH = "IDENTITY_MISMATCH"
PROCESS_NOT_FOUND = "PROCESS_NOT_FOUND"
VALIDATION_FAILED = "VALIDATION_FAILED"

# Tolerance window in seconds for creation_time comparison
# (some OS clocks have sub-second rounding differences)
CREATION_TIME_TOLERANCE_S = 2.0


def get_process_identity(pid: int) -> Optional[dict]:
    """
    Returns real-time process identity information for a given PID.
    Returns None if the process does not exist.
    """
    try:
        p = psutil.Process(pid)
        with p.oneshot():
            create_time = p.create_time()
            exe = ""
            try:
                exe = p.exe()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                exe = "ACCESS_DENIED"
            name = ""
            try:
                name = p.name()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                name = "ACCESS_DENIED"
            try:
                cmdline = " ".join(p.cmdline())
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                cmdline = "ACCESS_DENIED"

        return {
            "pid": pid,
            "creation_time": create_time,
            "creation_time_iso": datetime.utcfromtimestamp(create_time).isoformat(),
            "executable_path": exe,
            "name": name,
            "cmdline": cmdline,
        }
    except psutil.NoSuchProcess:
        return None
    except Exception as e:
        logger.warning(f"[ProcessIdentity] Error inspecting PID {pid}: {e}")
        return None


def build_process_instance_id(endpoint_id: str, pid: int, creation_time: float) -> str:
    """
    Constructs a stable, globally unique process instance ID.
    Format: <endpoint_id>:<pid>:<creation_time_hex>
    """
    ct_hex = format(int(creation_time * 1000), "x")
    return f"{endpoint_id}:{pid}:{ct_hex}"


def validate_process_identity(
    pid: int,
    recorded_creation_time: Optional[float] = None,
    recorded_executable: Optional[str] = None,
    tolerance_s: float = CREATION_TIME_TOLERANCE_S,
) -> Tuple[str, dict]:
    """
    Validates that the current PID still belongs to the same process instance.

    Args:
        pid: The target PID.
        recorded_creation_time: Creation time recorded when the alert was raised.
        recorded_executable: Executable path recorded at alert time.
        tolerance_s: Allowed drift in seconds between recorded and live creation times.

    Returns:
        (result_code: str, details: dict)
    """
    live = get_process_identity(pid)

    if live is None:
        return PROCESS_NOT_FOUND, {
            "pid": pid,
            "reason": f"PID {pid} no longer exists.",
        }

    details = {
        "pid": pid,
        "live_creation_time": live["creation_time"],
        "live_creation_time_iso": live["creation_time_iso"],
        "live_executable": live["executable_path"],
        "live_name": live["name"],
    }

    try:
        if recorded_creation_time is not None:
            diff = abs(live["creation_time"] - recorded_creation_time)
            details["creation_time_diff_s"] = round(diff, 4)
            details["recorded_creation_time"] = recorded_creation_time
            if diff > tolerance_s:
                details["reason"] = (
                    f"PID {pid} creation_time mismatch: recorded={recorded_creation_time:.3f} "
                    f"live={live['creation_time']:.3f} diff={diff:.3f}s > tolerance={tolerance_s}s. "
                    f"PID REUSE DETECTED."
                )
                return IDENTITY_MISMATCH, details

        if recorded_executable and live["executable_path"] not in ("ACCESS_DENIED", ""):
            if recorded_executable.lower() != live["executable_path"].lower():
                details["recorded_executable"] = recorded_executable
                details["reason"] = (
                    f"Executable mismatch: recorded={recorded_executable} "
                    f"live={live['executable_path']}. PID REUSE DETECTED."
                )
                return IDENTITY_MISMATCH, details

        details["reason"] = "Identity confirmed."
        return IDENTITY_VALID, details

    except Exception as e:
        logger.error(f"[ProcessIdentity] Validation error for PID {pid}: {e}")
        return VALIDATION_FAILED, {"pid": pid, "reason": str(e)}


class ProcessIdentityGuard:
    @staticmethod
    def validate_process_identity(
        pid: int,
        recorded_creation_time: Optional[float] = None,
        recorded_executable: Optional[str] = None
    ) -> dict:
        status, details = validate_process_identity(pid, recorded_creation_time, recorded_executable)
        return {"status": status, "details": details}

