import ctypes
import psutil
import os
import sys

def create_minidump(pid, filename):
    PROCESS_ALL_ACCESS = 0x1F0FFF
    kernel32 = ctypes.windll.kernel32
    dbghelp = ctypes.windll.dbghelp

    # OpenProcess
    h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h_process:
        print(f"Failed to open process. Error: {kernel32.GetLastError()}")
        return False

    # Create file
    GENERIC_WRITE = 0x40000000
    CREATE_ALWAYS = 2
    FILE_ATTRIBUTE_NORMAL = 0x80
    h_file = kernel32.CreateFileW(
        filename, GENERIC_WRITE, 0, None, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, None
    )
    if h_file == -1: # INVALID_HANDLE_VALUE
        print(f"Failed to create file. Error: {kernel32.GetLastError()}")
        kernel32.CloseHandle(h_process)
        return False

    # MiniDumpWriteDump
    # MiniDumpWithFullMemory = 0x00000002
    MINIDUMP_TYPE = 2 
    success = dbghelp.MiniDumpWriteDump(
        h_process, pid, h_file, MINIDUMP_TYPE, None, None, None
    )

    kernel32.CloseHandle(h_file)
    kernel32.CloseHandle(h_process)

    if success:
        print(f"Successfully dumped to {filename}")
        return True
    else:
        print(f"MiniDumpWriteDump failed. Error: {kernel32.GetLastError()}")
        return False

if __name__ == "__main__":
    import subprocess
    import time
    
    # Spawn dummy process
    dummy = subprocess.Popen([sys.executable, "backend/dummy_process.py"])
    time.sleep(1)
    
    dump_file = "test_dump.dmp"
    print(f"Dumping PID {dummy.pid}...")
    try:
        create_minidump(dummy.pid, dump_file)
    finally:
        if os.path.exists(dump_file):
            print(f"Dump file size: {os.path.getsize(dump_file)} bytes")
        dummy.kill()
