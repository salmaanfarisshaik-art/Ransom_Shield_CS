"""
RansomShield Endpoint Telemetry Collector
Aggregates filesystem, process, network, and Sysmon telemetry with provenance tags.
"""
import psutil
from datetime import datetime
from typing import List, Dict, Any
from backend.agent.agent_config import ENDPOINT_ID

class AgentTelemetryCollector:
    @staticmethod
    def get_process_list() -> List[Dict[str, Any]]:
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'create_time', 'cpu_percent', 'memory_percent']):
            try:
                pinfo = proc.info
                pid = pinfo['pid']
                ctime = datetime.fromtimestamp(pinfo['create_time']).isoformat()
                proc_inst_id = f"{ENDPOINT_ID}_{pid}_{int(pinfo['create_time'])}"
                processes.append({
                    "pid": pid,
                    "process_instance_id": proc_inst_id,
                    "name": pinfo['name'] or "unknown",
                    "executable_path": pinfo['exe'] or "",
                    "creation_time": ctime,
                    "cpu": round(pinfo['cpu_percent'] or 0.0, 1),
                    "memory": round(pinfo['memory_percent'] or 0.0, 1),
                    "status": "RUNNING"
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return processes[:50]
