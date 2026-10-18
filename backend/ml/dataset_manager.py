"""
RansomShield Dataset Manager (Section 7 & 11)
Manages labeled datasets for supervised ML training.

Label conventions:
  BENIGN                        - Clearly normal system activity
  CONTROLLED_TEST_RANSOMWARE_LIKE - Output from our controlled safe simulator
  (NOT 'RANSOMWARE' — we do not have real malware ground truth)

Never auto-labels data based on detector output (circular ground truth).
"""
import os
import csv
import json
import hashlib
import logging
from datetime import datetime
from typing import List, Optional, Dict, Any

logger = logging.getLogger(__name__)

DATASET_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "research_results", "datasets")
os.makedirs(DATASET_DIR, exist_ok=True)

VALID_LABELS = {"BENIGN", "CONTROLLED_TEST_RANSOMWARE_LIKE"}

FEATURE_SCHEMA = [
    "cpu_percent",
    "disk_write_mb_per_s",
    "fs_alert_count",
    "entropy_score",
    "rename_count",
    "unique_extensions_modified",
]


class DatasetManager:
    """Manages the labeled dataset for supervised ML training."""
    FEATURE_NAMES = FEATURE_SCHEMA


    @staticmethod
    def validate_label(label: str) -> bool:
        return label in VALID_LABELS

    @staticmethod
    def add_sample(
        label: str,
        features: Dict[str, float],
        endpoint_id: str = "local-host-01",
        source: str = "EXPERIMENT",
        dataset_version: str = "1.0",
        case_id: Optional[str] = None,
    ) -> dict:
        """Appends one labeled sample to the dataset CSV."""
        if label not in VALID_LABELS:
            raise ValueError(
                f"Invalid label '{label}'. Must be one of {VALID_LABELS}. "
                "Do NOT use 'RANSOMWARE' without explicit ground truth justification."
            )
        # Validate required features
        missing = [f for f in FEATURE_SCHEMA if f not in features]
        if missing:
            raise ValueError(f"Missing required features: {missing}")

        sample_id = hashlib.sha256(
            f"{datetime.utcnow().isoformat()}:{label}:{json.dumps(features)}".encode()
        ).hexdigest()[:16]

        row = {
            "sample_id": sample_id,
            "label": label,
            "endpoint_id": endpoint_id,
            "timestamp": datetime.utcnow().isoformat(),
            "case_id": case_id or "UNLINKED",
            "source": source,
            "dataset_version": dataset_version,
            **{f: features.get(f, 0.0) for f in FEATURE_SCHEMA},
        }

        csv_path = os.path.join(DATASET_DIR, f"dataset_v{dataset_version}.csv")
        file_exists = os.path.exists(csv_path)
        with open(csv_path, "a", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(row.keys()))
            if not file_exists:
                writer.writeheader()
            writer.writerow(row)

        return {"sample_id": sample_id, "label": label, "stored": True}

    @staticmethod
    def load_dataset(dataset_version: str = "1.0") -> List[dict]:
        """Loads all samples from dataset CSV."""
        csv_path = os.path.join(DATASET_DIR, f"dataset_v{dataset_version}.csv")
        if not os.path.exists(csv_path):
            return []
        with open(csv_path, "r") as f:
            reader = csv.DictReader(f)
            return list(reader)

    @staticmethod
    def get_dataset_stats(dataset_version: str = "1.0") -> dict:
        """Returns label distribution and feature count."""
        samples = DatasetManager.load_dataset(dataset_version)
        label_counts: Dict[str, int] = {}
        for s in samples:
            lbl = s.get("label", "UNKNOWN")
            label_counts[lbl] = label_counts.get(lbl, 0) + 1
        return {
            "dataset_version": dataset_version,
            "total_samples": len(samples),
            "label_distribution": label_counts,
            "feature_schema": FEATURE_SCHEMA,
            "csv_path": os.path.join(DATASET_DIR, f"dataset_v{dataset_version}.csv"),
        }

    @staticmethod
    def compute_dataset_hash(dataset_version: str = "1.0") -> str:
        """SHA-256 hash of the dataset CSV for reproducibility."""
        csv_path = os.path.join(DATASET_DIR, f"dataset_v{dataset_version}.csv")
        if not os.path.exists(csv_path):
            return "NO_DATASET"
        h = hashlib.sha256()
        with open(csv_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
