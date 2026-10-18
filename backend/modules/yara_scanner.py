"""
YARA Rule Scanner Module for RansomShield.
Provides standalone file, byte-buffer, and memory dump YARA scanning.

Handles missing YARA dependencies or uncompiled rules with graceful degradation.
"""

import os
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

RULES_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "rules", "generic_ransom_behavior.yar")

class YaraScanner:
    def __init__(self, rules_path: Optional[str] = None):
        self.rules_path = rules_path or RULES_PATH
        self.compiled_rules = None
        self.status = "UNINITIALIZED"

        if not YARA_AVAILABLE:
            self.status = "YARA_PACKAGE_NOT_INSTALLED"
            return

        if os.path.exists(self.rules_path):
            try:
                self.compiled_rules = yara.compile(filepath=self.rules_path)
                self.status = "READY"
            except Exception as e:
                logger.warning(f"Failed to compile YARA rules from {self.rules_path}: {e}")
                self.status = "COMPILE_ERROR"
        else:
            self.status = "RULES_FILE_NOT_FOUND"

    def scan_file(self, file_path: str) -> Dict[str, Any]:
        if self.status != "READY" or not self.compiled_rules:
            return {
                "status": self.status,
                "matched": False,
                "matches": [],
                "details": f"Scanner status: {self.status}"
            }

        if not os.path.exists(file_path):
            return {
                "status": "FILE_NOT_FOUND",
                "matched": False,
                "matches": [],
                "details": f"Target file {file_path} not found"
            }

        try:
            matches = self.compiled_rules.match(file_path)
            matched_names = [m.rule for m in matches]
            return {
                "status": "SUCCESS",
                "matched": len(matched_names) > 0,
                "matches": matched_names,
                "details": f"Matched rules: {', '.join(matched_names)}" if matched_names else "No YARA match."
            }
        except Exception as e:
            return {
                "status": "SCAN_ERROR",
                "matched": False,
                "matches": [],
                "details": str(e)
            }

    def scan_data(self, data_bytes: bytes) -> Dict[str, Any]:
        if self.status != "READY" or not self.compiled_rules:
            return {
                "status": self.status,
                "matched": False,
                "matches": [],
                "details": f"Scanner status: {self.status}"
            }

        try:
            matches = self.compiled_rules.match(data=data_bytes)
            matched_names = [m.rule for m in matches]
            return {
                "status": "SUCCESS",
                "matched": len(matched_names) > 0,
                "matches": matched_names,
                "details": f"Matched rules: {', '.join(matched_names)}" if matched_names else "No YARA match."
            }
        except Exception as e:
            return {
                "status": "SCAN_ERROR",
                "matched": False,
                "matches": [],
                "details": str(e)
            }
