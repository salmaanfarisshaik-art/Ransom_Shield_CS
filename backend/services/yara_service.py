"""
RansomShield YARA Signature Engine & Evidence Service (Phase H)
Scans memory dumps and files against compiled YARA rules, logging structured evidence and findings.
"""
import os
import yara
import logging
from datetime import datetime
from sqlalchemy.orm import Session
from backend.models.entities import YaraFindingRecord
from backend.services.evidence_service import compute_file_sha256, EvidenceService

logger = logging.getLogger(__name__)

RULES_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "rules", "generic_ransom_behavior.yar")

class YaraService:
    @staticmethod
    def get_compiled_rules():
        try:
            if os.path.exists(RULES_PATH):
                return yara.compile(filepath=RULES_PATH)
            return None
        except Exception as e:
            logger.error(f"Failed to compile YARA rules at {RULES_PATH}: {e}")
            return None

    @staticmethod
    def scan_memory_dump(
        db: Session,
        dump_filepath: str,
        memory_image_id: str = None,
        process_instance_id: str = None,
        endpoint_id: str = "local-host-01"
    ) -> dict:
        
        rules = YaraService.get_compiled_rules()
        if not rules:
            return {
                "status": "YARA_UNAVAILABLE",
                "match": False,
                "rule_names": [],
                "details": "YARA rules not loaded or unavailable."
            }

        if not os.path.exists(dump_filepath):
            return {
                "status": "SCAN_FAILED",
                "match": False,
                "rule_names": [],
                "details": f"Target dump file {dump_filepath} does not exist."
            }

        try:
            dump_hash = compute_file_sha256(dump_filepath)
            rule_hash = compute_file_sha256(RULES_PATH) if os.path.exists(RULES_PATH) else "0" * 64
            matches = rules.match(dump_filepath)

            if matches:
                matched_rule_names = [m.rule for m in matches]
                matched_strings = [str(s) for m in matches for s in getattr(m, 'strings', [])]

                finding = YaraFindingRecord(
                    rule_id="generic_ransom_behavior",
                    rule_name=", ".join(matched_rule_names),
                    rule_version="1.0.0",
                    rule_hash=rule_hash,
                    scan_target=dump_filepath,
                    scan_time=datetime.utcnow(),
                    match_count=len(matches),
                    matched_strings=matched_strings,
                    memory_image_id=memory_image_id,
                    process_instance_id=process_instance_id,
                    status="MATCH"
                )
                db.add(finding)
                db.commit()

                # Record unified evidence
                EvidenceService.record_evidence(
                    db=db,
                    endpoint_id=endpoint_id,
                    source_type="YARA",
                    event_type="YARA_MEMORY_MATCH",
                    observed_value=f"Matched rules: {', '.join(matched_rule_names)}",
                    process_instance_id=process_instance_id,
                    artifact=dump_filepath,
                    provenance="yara-python Engine",
                    confidence=0.9,
                    classification="OBSERVED"
                )

                return {
                    "status": "MATCH",
                    "match": True,
                    "rule_names": matched_rule_names,
                    "details": f"YARA matched rules: {', '.join(matched_rule_names)}"
                }
            else:
                finding = YaraFindingRecord(
                    rule_id="generic_ransom_behavior",
                    rule_name="None",
                    rule_version="1.0.0",
                    rule_hash=rule_hash,
                    scan_target=dump_filepath,
                    scan_time=datetime.utcnow(),
                    match_count=0,
                    matched_strings=[],
                    memory_image_id=memory_image_id,
                    process_instance_id=process_instance_id,
                    status="NO_MATCH"
                )
                db.add(finding)
                db.commit()

                return {
                    "status": "NO_MATCH",
                    "match": False,
                    "rule_names": [],
                    "details": "No YARA signatures matched."
                }

        except Exception as e:
            logger.error(f"YARA scan failed for {dump_filepath}: {e}")
            return {
                "status": "SCAN_FAILED",
                "match": False,
                "rule_names": [],
                "details": f"Error during YARA scan: {str(e)}"
            }
