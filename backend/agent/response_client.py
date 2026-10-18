"""
RansomShield Endpoint Agent Response Client
Sends heartbeats, registers host, and listens for containment response actions.
"""
import time
import json
import logging
import urllib.request
import urllib.error
from typing import Dict, Any
from backend.agent.agent_config import API_BASE, API_KEY, ENDPOINT_ID, AGENT_VERSION, HOSTNAME, OS_VERSION, IP_ADDRESS
from backend.agent.agent_heartbeat import AgentHeartbeatCollector
from backend.agent.process_controller import AgentProcessController
from backend.agent.isolation_controller import AgentIsolationController

logger = logging.getLogger(__name__)

class AgentResponseClient:
    def __init__(self, api_base: str = API_BASE, api_key: str = API_KEY):
        self.api_base = api_base
        self.api_key = api_key
        self.registered = False

    def register(self) -> bool:
        url = f"{self.api_base}/endpoints/register"
        payload = json.dumps({
            "endpoint_id": ENDPOINT_ID,
            "hostname": HOSTNAME,
            "os": OS_VERSION,
            "agent_version": AGENT_VERSION,
            "ip_address": IP_ADDRESS
        }).encode()

        try:
            req = urllib.request.Request(
                url, data=payload,
                headers={"Content-Type": "application/json", "x-api-key": self.api_key},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status in (200, 201):
                    self.registered = True
                    logger.info(f"Endpoint {ENDPOINT_ID} registered successfully with RansomShield Backend.")
                    return True
        except Exception as e:
            logger.warning(f"Endpoint registration ping failed ({e}). Proceeding in standalone agent mode.")
        return False

    def send_heartbeat(self) -> Dict[str, Any]:
        metrics = AgentHeartbeatCollector.collect_metrics()
        url = f"{self.api_base}/endpoints/{ENDPOINT_ID}/heartbeat"
        payload = json.dumps(metrics).encode()

        try:
            req = urllib.request.Request(
                url, data=payload,
                headers={"Content-Type": "application/json", "x-api-key": self.api_key},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                res_data = json.loads(resp.read())
                return res_data
        except Exception as e:
            logger.debug(f"Heartbeat post error: {e}")
        return metrics
