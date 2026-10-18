"""
Ground Truth & Controlled Experiment Case Definitions for RansomShield.
Defines explicit expected behavior, ground truth classifications, and evaluation methods.

ZERO-FABRICATION RULE:
Metrics MUST be calculated by comparing actual observed detections against registered ground truth events.
Labels for synthetic/simulator workloads MUST use CONTROLLED_TEST_RANSOMWARE_LIKE.
"""

import os
import json
import time
import uuid
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field, asdict

# Strict classification labels
LABEL_BENIGN = "BENIGN"
LABEL_CONTROLLED_RANSOMWARE_LIKE = "CONTROLLED_TEST_RANSOMWARE_LIKE"
VALID_LABELS = {LABEL_BENIGN, LABEL_CONTROLLED_RANSOMWARE_LIKE}

@dataclass
class GroundTruthEvent:
    event_id: str
    scenario_id: str
    pid: int
    process_name: str
    expected_label: str  # BENIGN or CONTROLLED_TEST_RANSOMWARE_LIKE
    expected_detection: bool  # True if expected to be flagged
    target_path: Optional[str] = None
    action_type: str = "FILE_OPERATION"
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class ObservedDetection:
    detection_id: str
    scenario_id: str
    pid: int
    process_name: str
    flagged: bool
    confidence: float
    risk_score: float
    detection_sources: List[str]  # e.g., ["FS_MONITOR", "YARA", "VOLATILITY"]
    raw_alert: Optional[Dict[str, Any]] = None
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class ExperimentCase:
    case_id: str
    name: str
    description: str
    ground_truth_label: str
    enabled_components: List[str]  # e.g. ["FS_MONITOR", "SYSMON", "YARA", "VOLATILITY", "ML", "CORRELATION"]
    params: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

class GroundTruthRegistry:
    """
    Stores and evaluates Ground Truth vs Observed Detections for experiment validation.
    """
    def __init__(self, experiment_id: str):
        self.experiment_id = experiment_id
        self.ground_truths: Dict[str, GroundTruthEvent] = {} # key: event_id or pid
        self.observed_detections: List[ObservedDetection] = []

    def register_ground_truth(self, event: GroundTruthEvent):
        if event.expected_label not in VALID_LABELS:
            raise ValueError(f"Invalid label '{event.expected_label}'. Must be one of {VALID_LABELS}")
        self.ground_truths[event.event_id] = event

    def register_observation(self, obs: ObservedDetection):
        self.observed_detections.append(obs)

    def evaluate_metrics(self) -> Dict[str, Any]:
        """
        Computes empirical TP, FP, TN, FN based on registered ground truth and actual observations.
        """
        tp = 0
        fp = 0
        tn = 0
        fn = 0
        unmatched_observations = 0

        # Map pid to ground truth
        gt_by_pid: Dict[int, GroundTruthEvent] = {}
        for gt in self.ground_truths.values():
            gt_by_pid[gt.pid] = gt

        # Process observed detections
        evaluated_pids = set()
        for obs in self.observed_detections:
            if obs.pid in gt_by_pid:
                gt = gt_by_pid[obs.pid]
                evaluated_pids.add(obs.pid)
                if gt.expected_label == LABEL_CONTROLLED_RANSOMWARE_LIKE:
                    if obs.flagged:
                        tp += 1
                    else:
                        fn += 1
                elif gt.expected_label == LABEL_BENIGN:
                    if obs.flagged:
                        fp += 1
                    else:
                        tn += 1
            else:
                unmatched_observations += 1

        # Check ground truths that received NO observation
        for pid, gt in gt_by_pid.items():
            if pid not in evaluated_pids:
                if gt.expected_label == LABEL_CONTROLLED_RANSOMWARE_LIKE:
                    if gt.expected_detection:
                        fn += 1
                    else:
                        tn += 1
                elif gt.expected_label == LABEL_BENIGN:
                    tn += 1

        total_samples = tp + fp + tn + fn
        precision = round(tp / (tp + fp), 4) if (tp + fp) > 0 else 0.0
        recall = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 0.0
        f1 = round((2 * precision * recall) / (precision + recall), 4) if (precision + recall) > 0 else 0.0
        fpr = round(fp / (fp + tn), 4) if (fp + tn) > 0 else 0.0

        return {
            "experiment_id": self.experiment_id,
            "tp": tp,
            "fp": fp,
            "tn": tn,
            "fn": fn,
            "total_samples": total_samples,
            "unmatched_observations": unmatched_observations,
            "precision": precision,
            "recall": recall,
            "f1_score": f1,
            "fpr": fpr,
            "has_ground_truth": len(self.ground_truths) > 0
        }

# Pre-defined Research Experiment Cases (CASE-RS-01 to CASE-RS-05)
STANDARD_TEST_CASES = {
    "CASE-RS-01": ExperimentCase(
        case_id="CASE-RS-01",
        name="Entropy Only",
        description="High-entropy file modification on target files without extension change",
        ground_truth_label=LABEL_CONTROLLED_RANSOMWARE_LIKE,
        enabled_components=["FS_MONITOR"],
        params={"rename": False, "entropy_threshold": 7.2, "spawn_process": False}
    ),
    "CASE-RS-02": ExperimentCase(
        case_id="CASE-RS-02",
        name="Rename Only",
        description="Mass extension renaming without high entropy change",
        ground_truth_label=LABEL_CONTROLLED_RANSOMWARE_LIKE,
        enabled_components=["FS_MONITOR"],
        params={"rename": True, "entropy_threshold": 4.0, "spawn_process": False}
    ),
    "CASE-RS-03": ExperimentCase(
        case_id="CASE-RS-03",
        name="Entropy + Rename",
        description="Combined high-entropy modification and mass extension rename",
        ground_truth_label=LABEL_CONTROLLED_RANSOMWARE_LIKE,
        enabled_components=["FS_MONITOR", "YARA"],
        params={"rename": True, "entropy_threshold": 7.5, "spawn_process": False}
    ),
    "CASE-RS-04": ExperimentCase(
        case_id="CASE-RS-04",
        name="Entropy + Rename + Process Spawn",
        description="Entropy + Rename + malicious process spawning attempt",
        ground_truth_label=LABEL_CONTROLLED_RANSOMWARE_LIKE,
        enabled_components=["FS_MONITOR", "YARA", "SYSMON"],
        params={"rename": True, "entropy_threshold": 7.5, "spawn_process": True}
    ),
    "CASE-RS-05": ExperimentCase(
        case_id="CASE-RS-05",
        name="Full Attack Sequence",
        description="Entropy + Rename + Process Spawn + Shadow Copy Deletion + Registry Persistence",
        ground_truth_label=LABEL_CONTROLLED_RANSOMWARE_LIKE,
        enabled_components=["FS_MONITOR", "SYSMON", "YARA", "VOLATILITY", "ML", "CORRELATION"],
        params={"rename": True, "entropy_threshold": 7.8, "spawn_process": True, "shadow_copy": True}
    ),
}
