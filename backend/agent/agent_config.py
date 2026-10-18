"""
RansomShield Windows Endpoint Agent Configuration
"""
import os
import platform
import socket

AGENT_VERSION = "2.5.0"
ENDPOINT_ID = os.getenv("RANSOMSHIELD_ENDPOINT_ID", "local-host-01")
HOSTNAME = socket.gethostname()
OS_VERSION = f"{platform.system()} {platform.release()}"
IP_ADDRESS = socket.gethostbyname(HOSTNAME) if HOSTNAME else "127.0.0.1"

API_BASE = os.getenv("RANSOMSHIELD_API_BASE", "http://127.0.0.1:8000/api")
API_KEY = os.getenv("RANSOMSHIELD_API_KEY", "changeme-in-production")

HEARTBEAT_INTERVAL_SECONDS = 5
TELEMETRY_INTERVAL_SECONDS = 3
