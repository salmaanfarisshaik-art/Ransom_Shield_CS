"""
RansomShield Protected Endpoint Agent Main Entry Point
Runs on the protected host to provide continuous host registration,
telemetry aggregation, process identity enforcement, and containment execution.
"""
import time
import logging
import sys
from backend.agent.agent_config import ENDPOINT_ID, HEARTBEAT_INTERVAL_SECONDS
from backend.agent.response_client import AgentResponseClient

logging.basicConfig(level=logging.INFO, format="[RANSOMSHIELD AGENT] %(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

def run_agent(single_loop: bool = False):
    logger.info(f"Initializing RansomShield Protected Endpoint Agent for {ENDPOINT_ID}...")
    client = AgentResponseClient()
    client.register()

    logger.info("Agent started. Listening for telemetry & containment commands...")

    try:
        while True:
            hb = client.send_heartbeat()
            logger.info(f"Heartbeat sent: CPU={hb.get('cpu_percent')}% | RAM={hb.get('ram_percent')}% | Status={hb.get('agent_status')}")
            if single_loop:
                break
            time.sleep(HEARTBEAT_INTERVAL_SECONDS)
    except KeyboardInterrupt:
        logger.info("Agent daemon stopped by operator.")

if __name__ == "__main__":
    single = "--single" in sys.argv
    run_agent(single_loop=single)
