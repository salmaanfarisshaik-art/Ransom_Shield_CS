"""
Model Evaluation & Explainability (SHAP) Utilities for RansomShield.

RULES:
- SHAP feature importance is ONLY calculated for Supervised Models (RandomForestClassifier).
- SHAP MUST NEVER claim to explain unsupervised IsolationForest.
- Confusion matrix computations must handle zero-denominator cases gracefully.
"""

import os
import numpy as np
from typing import Dict, Any, List, Optional

try:
    import shap
    SHAP_AVAILABLE = True
except ImportError:
    SHAP_AVAILABLE = False

from .dataset_manager import DatasetManager

class MLEvaluator:
    @staticmethod
    def calculate_shap_values(model: Any, feature_vector: List[float], feature_names: List[str] = DatasetManager.FEATURE_NAMES) -> Dict[str, Any]:
        """
        Calculates SHAP explainability metrics for a given supervised model prediction.
        Returns empty structure with error message if model is unsupervised or SHAP is unavailable.
        """
        model_type = type(model).__name__

        if "IsolationForest" in model_type:
            return {
                "status": "UNSUPPORTED_MODEL_TYPE",
                "message": "SHAP feature attribution is supported ONLY for supervised classifiers (e.g., RandomForest), NOT unsupervised IsolationForest.",
                "feature_contributions": {}
            }

        if not SHAP_AVAILABLE:
            # Fallback to model feature importances if SHAP package not installed
            if hasattr(model, "feature_importances_"):
                importances = dict(zip(feature_names, model.feature_importances_.round(4).tolist()))
                return {
                    "status": "FALLBACK_FEATURE_IMPORTANCE",
                    "message": "SHAP package not installed; returning standard tree feature importances.",
                    "feature_contributions": importances
                }
            return {
                "status": "SHAP_UNAVAILABLE",
                "message": "SHAP library is not installed in current python environment.",
                "feature_contributions": {}
            }

        try:
            explainer = shap.TreeExplainer(model)
            X_in = np.array(feature_vector).reshape(1, -1)
            shap_values = explainer.shap_values(X_in)

            # For binary classification, shap_values might be a list of 2 arrays or single array
            if isinstance(shap_values, list):
                vals = shap_values[1][0] # class 1 (ransomware-like)
            elif len(shap_values.shape) == 3:
                vals = shap_values[0, :, 1]
            else:
                vals = shap_values[0]

            contributions = dict(zip(feature_names, [round(float(v), 4) for v in vals]))

            return {
                "status": "SUCCESS",
                "model_type": model_type,
                "base_value": float(explainer.expected_value[1]) if isinstance(explainer.expected_value, (list, np.ndarray)) else float(explainer.expected_value),
                "feature_contributions": contributions
            }
        except Exception as e:
            return {
                "status": "CALCULATION_ERROR",
                "message": str(e),
                "feature_contributions": {}
            }

    @staticmethod
    def compute_confusion_matrix(tp: int, fp: int, tn: int, fn: int) -> Dict[str, Any]:
        """
        Computes standard metrics and confusion matrix format.
        """
        total = tp + fp + tn + fn
        precision = round(tp / (tp + fp), 4) if (tp + fp) > 0 else "N/A"
        recall = round(tp / (tp + fn), 4) if (tp + fn) > 0 else "N/A"

        if isinstance(precision, float) and isinstance(recall, float) and (precision + recall) > 0:
            f1 = round((2 * precision * recall) / (precision + recall), 4)
        else:
            f1 = "N/A"

        fpr = round(fp / (fp + tn), 4) if (fp + tn) > 0 else "N/A"
        accuracy = round((tp + tn) / total, 4) if total > 0 else "N/A"

        return {
            "matrix": {
                "TP": tp,
                "FP": fp,
                "TN": tn,
                "FN": fn
            },
            "metrics": {
                "precision": precision,
                "recall": recall,
                "f1_score": f1,
                "fpr": fpr,
                "accuracy": accuracy
            }
        }
