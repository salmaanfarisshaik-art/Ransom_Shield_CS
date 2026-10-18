import ctypes
import os
# pyrefly: ignore [missing-import]
import yara
import logging

logger = logging.getLogger(__name__)

# Load the YARA rule once at startup
RULES_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "rules", "generic_ransom_behavior.yar")
try:
    compiled_rules = yara.compile(filepath=RULES_PATH)
except Exception as e:
    logger.warning(f"Could not compile YARA rules at {RULES_PATH}: {e}")
    compiled_rules = None

def acquire_minidump(pid: int, dump_path: str) -> bool:
    """
    Creates a MiniDump of the specified PID using Windows dbghelp.dll.
    Returns True if successful.
    """
    PROCESS_ALL_ACCESS = 0x1F0FFF
    kernel32 = ctypes.windll.kernel32
    dbghelp = ctypes.windll.dbghelp

    h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h_process:
        logger.error(f"Failed to open process {pid} for memory acquisition.")
        return False

    GENERIC_WRITE = 0x40000000
    CREATE_ALWAYS = 2
    FILE_ATTRIBUTE_NORMAL = 0x80
    
    h_file = kernel32.CreateFileW(
        dump_path, GENERIC_WRITE, 0, None, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, None
    )
    if h_file == -1: # INVALID_HANDLE_VALUE
        logger.error(f"Failed to create dump file {dump_path}.")
        kernel32.CloseHandle(h_process)
        return False

    MINIDUMP_TYPE = 2 # MiniDumpWithFullMemory (scans all accessible pages in user mode)
    success = dbghelp.MiniDumpWriteDump(
        h_process, pid, h_file, MINIDUMP_TYPE, None, None, None
    )

    kernel32.CloseHandle(h_file)
    kernel32.CloseHandle(h_process)

    return bool(success)

def acquire_and_scan_memory(pid: int) -> dict:
    """
    Performs the full pipeline: Dump -> Scan -> Delete.
    Returns a dict with {"match": bool, "details": str}.
    """
    if not compiled_rules:
        return {"match": False, "details": "YARA rules not loaded."}
        
    dump_dir = os.path.join(os.path.dirname(__file__), "..", "data", "memory_dumps")
    os.makedirs(dump_dir, exist_ok=True)
    
    dump_file = os.path.join(dump_dir, f"proc_{pid}.dmp")
    
    try:
        # Step 1: Dump
        success = acquire_minidump(pid, dump_file)
        if not success:
            return {"match": False, "details": "Memory acquisition failed."}
            
        # Step 2: Scan
        matches = compiled_rules.match(dump_file)
        if matches:
            rule_names = [m.rule for m in matches]
            return {
                "match": True, 
                "details": f"YARA match: {', '.join(rule_names)}"
            }
        else:
            return {"match": False, "details": "No YARA match."}
            
    except Exception as e:
        logger.error(f"Memory forensics pipeline failed for PID {pid}: {e}")
        return {"match": False, "details": f"Error during memory scan: {e}"}
        
    finally:
        # Step 3: Delete
        if os.path.exists(dump_file):
            try:
                os.remove(dump_file)
            except Exception as e:
                logger.error(f"Failed to delete memory dump {dump_file}: {e}")
