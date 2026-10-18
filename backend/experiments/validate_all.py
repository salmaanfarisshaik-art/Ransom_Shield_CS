"""
Master Research Validation Command for RansomShield.
Executes full benchmark suite (B1-B5), zero-fabrication validation, E2E pipeline test,
and exports all research publication artifacts into research_results/

Usage:
  python -m backend.experiments.validate_all
"""

import os
import sys
import json

from .runner import ExperimentRunner
from .validator import ResearchDataValidator
from .e2e_test import E2EExperimentTest

def main():
    print("=" * 70)
    print("      RANSOMSHIELD MASTER RESEARCH EXPERIMENT & VALIDATION SUITE      ")
    print("=" * 70)

    # Step 1: Run E2E Test
    print("\n[*] Step 1/3: Running 16-Stage Reproducible E2E Pipeline Test (CONTROLLED_TEST_E2E_001)...")
    e2e_res = E2EExperimentTest.run_e2e_test()
    print(f"    -> Status: {e2e_res['status']} | Completed Stages: {e2e_res.get('total_stages', 0)}/16")

    # Step 2: Run Baselines B1-B5
    print("\n[*] Step 2/3: Running Empirical Baseline Benchmarks B1–B5 against Ground Truth...")
    runner_res = ExperimentRunner.run_all_baselines(repetitions=3)
    print(f"    -> Status: {runner_res['status']} | Results Directory: {runner_res['results_dir']}")
    print("    -> Summary of Empirical Baselines:")
    for b in runner_res["summary"]:
        print(f"       [{b['Baseline']} - {b['Name']}]: Precision={b['Precision']}, Recall={b['Recall']}, F1={b['F1_Score']}, FPR={b['FPR']}, Latency={b['Latency_ms']}ms")

    # Step 3: Zero-Fabrication Integrity Audit
    print("\n[*] Step 3/3: Auditing Research Artifact Integrity & Zero-Fabrication Compliance...")
    val_res = ResearchDataValidator.validate_all()
    print(f"    -> Status: {val_res['status']} | Zero Fabrication Confirmed: {val_res['zero_fabrication_confirmed']}")
    print(f"    -> Total Checks Passed: {len(val_res['checks'])}")
    if val_res["errors"]:
        print(f"    -> Errors: {val_res['errors']}")

    print("\n" + "=" * 70)
    print("      RESEARCH PACKAGE & EXPERIMENT VALIDATION COMPLETE      ")
    print("=" * 70)

if __name__ == "__main__":
    main()
