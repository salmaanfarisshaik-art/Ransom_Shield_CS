"""
RansomShield Kali Integration Configuration
Defensive Security Laboratory Test Controls
"""
import os

KALI_LAB_DEFAULT_ID = "Kali-Lab-01"
KALI_SOURCE_NAME = "Kali-Lab-01"
KALI_SOURCE_TYPE = "CONTROLLED_TEST_GENERATOR"
DEFAULT_TARGET_ENDPOINT = "local-host-01"

# Safety settings: NO arbitrary remote command execution allowed
ALLOW_ARBITRARY_COMMANDS = False
ALLOW_DESTRUCTIVE_ACTIONS = False

# Heartbeat interval in seconds
KALI_HEARTBEAT_INTERVAL = 5.0
KALI_SESSION_TTL_MINUTES = 60

DATA_ORIGIN_TAG = "CONTROLLED_TEST"
