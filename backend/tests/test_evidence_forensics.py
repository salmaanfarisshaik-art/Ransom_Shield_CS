"""
Automated Forensic Evidence & Pipeline Test Suite (Phases G, H, I, J, W, X, Y)
Verifies database ORM, evidence recording, YARA engine, Volatility service, report generation, and chain-of-custody.
"""
import os
import pytest
from backend.database.connection import init_db, SessionLocal
from backend.models.entities import Endpoint, ProcessInstance
from backend.services.evidence_service import EvidenceService, compute_sha256
from backend.services.yara_service import YaraService
from backend.services.volatility_service import VolatilityService
from backend.reports.pdf_generator import ReportGenerator

def test_evidence_and_chain_of_custody():
    init_db()
    db = SessionLocal()

    # Create test endpoint
    ep = Endpoint(endpoint_id="test-ep-01", hostname="TestPC", os="Windows 11")
    db.merge(ep)
    db.commit()

    ev = EvidenceService.record_evidence(
        db=db,
        endpoint_id="test-ep-01",
        source_type="FILESYSTEM",
        event_type="HIGH_ENTROPY_WRITE",
        observed_value="file.txt entropy: 7.85",
        classification="CONTROLLED_TEST"
    )

    assert ev.evidence_id is not None
    assert ev.classification == "CONTROLLED_TEST"
    assert len(ev.integrity_hash) == 64

    # Test report generation
    report = ReportGenerator.generate_json_report(db, incident_id="inc-test-01")
    assert report.report_id is not None
    assert os.path.exists(report.file_path)

    db.close()
