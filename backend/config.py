"""
RansomShield Configuration
"""
import os

# Filesystem Monitor Tunable Thresholds
FS_MONITOR_CONFIG = {
    "time_window_seconds": 10,
    "rename_threshold": 5,             # Number of renames within the time window to trigger alert
    "high_entropy_threshold": 7.5,     # Shannon entropy > 7.5 usually indicates encrypted/compressed data (max is 8.0)
    "entropy_write_threshold": 3       # Number of high entropy writes within time window
}

# System Monitor Tunable Settings
SYS_MONITOR_CONFIG = {
    "poll_interval_seconds": 5,        # How often sys_monitor collects and pushes metrics to the API
    "cpu_spike_threshold": 60.0,       # CPU usage percentage considered anomalous
    "disk_write_spike_mb": 10.0,       # Disk write MB/s considered anomalous within a single poll interval
}

# ML Anomaly Engine Tunable Settings
ML_ANOMALY_CONFIG = {
    # IsolationForest contamination: estimated fraction of anomalies in training data.
    # We use 0.1 since our synthetic data is ~10% attack samples.
    "isolation_forest_contamination": 0.1,
    "isolation_forest_n_estimators": 100,
    # Risk score returned when the model classifies a sample as anomalous (0-100 scale)
    "anomaly_risk_score": 90,
    # Risk score returned for borderline cases (score is near the decision boundary)
    "borderline_risk_score": 50,
    # Decision score threshold below which a sample is considered "borderline"
    # IsolationForest scores < 0 are anomalies; more negative = more anomalous
    "borderline_score_threshold": -0.05,
}

# API Security
API_AUTH_TOKEN = os.getenv("RANSOMSHIELD_API_KEY", "changeme-in-production")
