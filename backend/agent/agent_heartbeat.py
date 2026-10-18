"""
RansomShield Endpoint Agent Heartbeat Collector
Collects CPU, RAM, Disk, and Network metrics on the Windows Protected Endpoint.
"""
import psutil
import time
from datetime import datetime
from typing import Dict, Any
from backend.agent.agent_config import ENDPOINT_ID, AGENT_VERSION, HOSTNAME, OS_VERSION, IP_ADDRESS

class AgentHeartbeatCollector:
    @staticmethod
    def collect_metrics() -> Dict[str, Any]:
        cpu = psutil.cpu_percent(interval=0.1)
        ram = psutil.virtual_memory().percent
        disk = psutil.disk_usage('/').percent
        
        # Calculate network throughput (approximate)
        net = psutil.net_io_counters()
        kbps = (net.bytes_sent + net.bytes_recv) / 1024.0

        return {
            "endpoint_id": ENDPOINT_ID,
            "hostname": HOSTNAME,
            "os": OS_VERSION,
            "agent_version": AGENT_VERSION,
            "ip_address": IP_ADDRESS,
            "timestamp": datetime.utcnow().isoformat(),
            "cpu_percent": round(cpu, 1),
            "ram_percent": round(ram, 1),
            "disk_usage": round(disk, 1),
            "network_kbps": round(kbps, 1),
            "agent_status": "ONLINE"
        }
