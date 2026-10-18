# RansomShield IEEE/Scopus Research Package

This package contains all empirical research artifacts, ground-truth benchmarks (B1–B5), 
confusion matrices, publication-ready black-and-white graphs, and environment manifests 
for the RansomShield platform.

## Artifact Contents:
- aseline_metrics.csv: Empirical accuracy, latency, and resource overhead across Baselines B1–B5.
- blation_results.csv: Multi-evidence component contribution ablation.
- confusion_matrices.csv: Ground-truth TP, FP, TN, FN counts for B1 through B5.
- experiment_manifest.json: Environment, hardware, and timestamp audit trail.
- 
esearch_validation_report.json: Zero-fabrication math consistency audit report.
- graphs/: 12 publication-grade black-and-white 300 DPI PNG figures.

## Reproducibility Command:
`ash
python -m backend.experiments.validate_all
`
