"""
ML Anomaly Engine
-----------------
Uses scikit-learn's IsolationForest to detect anomalous system behavior
patterns consistent with ransomware activity.

IMPORTANT — SYNTHETIC DATA DISCLAIMER (for patent write-up):
    This model is trained exclusively on synthetically generated data
    that mimics "normal" vs. "attack" behavior patterns. It has NOT been
    trained on real ransomware telemetry or production system logs.
    Accuracy claims based on this training data are NOT representative of
    real-world detection rates and must not be presented as such in any
    patent claim or publication without this qualification.

Feature vector used:  [cpu_percent, disk_write_mb_per_s, fs_alert_count]
"""
import threading
import numpy as np
from sklearn.ensemble import IsolationForest

from backend.config import ML_ANOMALY_CONFIG


class AnomalyDetector:
    """
    Thread-safe wrapper around IsolationForest for ransomware anomaly detection.

    Concurrency design:
        - A threading.Lock guards all writes to the model and score state.
        - `predict()` acquires the lock only briefly to read the fitted model
          reference, then releases it before running the (read-only) inference.
          This means concurrent GET /api/risk-score requests never block each
          other — they only block for the microsecond it takes to grab the
          model reference, not the full inference time.
        - `update_risk_score()` (called from POST /api/internal/sys_metrics)
          acquires the lock to write the resulting score integer.  Because an
          integer assignment is effectively atomic in CPython, the real
          protection here is future-proofing against compound updates.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._model = None          # IsolationForest instance, set after calibrate()
        self._risk_score = 0        # Current computed risk score (0-100)
        self._calibrated = False

    # ------------------------------------------------------------------
    # Training
    # ------------------------------------------------------------------

    def calibrate(self):
        """
        Train the IsolationForest on synthetic behavioral data.

        Synthetic dataset design (read before modifying):
            - Normal samples: low CPU (<= ~30 %), low disk writes (<= ~5 MB/s),
              zero filesystem alerts — with Gaussian noise added so samples are
              NOT perfectly separated from attack samples.
            - Attack samples: elevated CPU (40–95 %), high disk writes (8–50
              MB/s), and 1–20 filesystem alerts — also with Gaussian noise.
            - The noise deliberately creates overlap between the two classes
              (e.g., a "normal" sample can momentarily look spiky), which
              gives the IsolationForest a more honest calibration signal.

        SYNTHETIC DATA NOTE: This does not represent production data.
        """
        rng = np.random.default_rng(seed=42)

        n_normal = 400
        n_attack = 50   # ~11 % contamination — consistent with config value

        # --- Normal samples -------------------------------------------------
        # cpu_percent: centred around 15 %, std 10 %
        cpu_normal = rng.normal(loc=15.0, scale=10.0, size=n_normal).clip(0, 100)
        # disk_write_mb_per_s: centred around 1.5 MB/s, std 1.5
        disk_normal = rng.normal(loc=1.5, scale=1.5, size=n_normal).clip(0, None)
        # fs_alert_count: mostly 0, occasionally 1 (background noise)
        fs_normal = rng.choice([0, 1], size=n_normal, p=[0.95, 0.05])

        normal_samples = np.column_stack([cpu_normal, disk_normal, fs_normal])

        # --- Attack samples -------------------------------------------------
        # cpu_percent: centred around 70 %, std 15 % (can dip into normal range)
        cpu_attack = rng.normal(loc=70.0, scale=15.0, size=n_attack).clip(0, 100)
        # disk_write_mb_per_s: centred around 25 MB/s, std 10
        disk_attack = rng.normal(loc=25.0, scale=10.0, size=n_attack).clip(0, None)
        # fs_alert_count: 3–15 alerts, with occasional low values overlapping normal
        fs_attack = rng.integers(low=1, high=16, size=n_attack)

        attack_samples = np.column_stack([cpu_attack, disk_attack, fs_attack])

        # --- Combine and train ----------------------------------------------
        X_train = np.vstack([normal_samples, attack_samples])

        model = IsolationForest(
            n_estimators=ML_ANOMALY_CONFIG["isolation_forest_n_estimators"],
            contamination=ML_ANOMALY_CONFIG["isolation_forest_contamination"],
            random_state=42
        )
        model.fit(X_train)

        with self._lock:
            self._model = model
            self._calibrated = True

        print("[ML] AnomalyDetector calibrated on synthetic dataset "
              f"({n_normal} normal + {n_attack} attack samples, with noise overlap).")
        print("[ML] NOTE: This is a synthetic-data-only model. "
              "Do not interpret its scores as production-validated accuracy.")

    # ------------------------------------------------------------------
    # Inference
    # ------------------------------------------------------------------

    def predict(self, cpu_percent: float, disk_write_mb: float, fs_alert_count: int) -> dict:
        """
        Score the current system state and return a risk assessment dict.

        Returns:
            {
                "is_anomaly": bool,
                "decision_score": float,   # raw IsolationForest score
                "risk_score": int,         # 0-100 for the dashboard
                "calibrated": bool
            }
        """
        # Grab the model reference under the lock (very fast — just a pointer read)
        with self._lock:
            model = self._model
            calibrated = self._calibrated

        if not calibrated or model is None:
            return {"is_anomaly": False, "decision_score": 0.0, "risk_score": 0, "calibrated": False}

        sample = np.array([[cpu_percent, disk_write_mb, float(fs_alert_count)]])
        decision_score = float(model.decision_function(sample)[0])
        prediction = int(model.predict(sample)[0])  # 1 = normal, -1 = anomaly

        is_anomaly = (prediction == -1)

        if is_anomaly:
            risk_score = ML_ANOMALY_CONFIG["anomaly_risk_score"]
        elif decision_score < ML_ANOMALY_CONFIG["borderline_score_threshold"]:
            risk_score = ML_ANOMALY_CONFIG["borderline_risk_score"]
        else:
            # Scale a low-risk score proportionally from the decision score (0-40 range)
            # decision_score > 0 means clearly normal; higher = more normal
            normalised = min(decision_score / 0.5, 1.0)   # cap at 0.5 → 0 risk
            risk_score = max(0, int((1 - normalised) * 40))

        return {
            "is_anomaly": is_anomaly,
            "decision_score": decision_score,
            "risk_score": risk_score,
            "calibrated": True
        }

    def update_risk_score(self, score: int):
        """Thread-safe setter for the current risk score."""
        with self._lock:
            self._risk_score = score

    def get_risk_score(self) -> int:
        """Thread-safe getter for the current risk score."""
        with self._lock:
            return self._risk_score


# Module-level singleton — shared by the FastAPI route handlers
detector = AnomalyDetector()
