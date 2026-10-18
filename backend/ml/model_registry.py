"""
Model Registry for RansomShield Machine Learning Models.
Manages versioned, hash-verified supervised and unsupervised ML models.

Rules:
- Never silently overwrite an existing versioned model file.
- Compute SHA-256 hash for every saved model artifact.
- Persist metadata alongside model artifacts.
"""

import os
import json
import hashlib
import pickle
import time
from typing import Dict, Any, Optional

MODELS_DIR = os.path.join(os.path.dirname(__file__), "..", "models_store")
os.makedirs(MODELS_DIR, exist_ok=True)

class ModelRegistry:
    @staticmethod
    def _compute_sha256(file_path: str) -> str:
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        return sha256.hexdigest()

    @classmethod
    def save_model(cls, model_obj: Any, model_name: str, version: str, metadata: Dict[str, Any]) -> str:
        """
        Saves a trained model artifact with versioning and SHA-256 hash.
        Raises FileExistsError if version exists and overwrite is False.
        """
        filename = f"{model_name}_v{version}.pkl"
        file_path = os.path.join(MODELS_DIR, filename)

        if os.path.exists(file_path):
            raise FileExistsError(f"Model artifact {filename} already exists. Version overwriting is prohibited.")

        with open(file_path, 'wb') as f:
            pickle.dump(model_obj, f)

        model_hash = cls._compute_sha256(file_path)

        meta = {
            "model_name": model_name,
            "version": version,
            "file_name": filename,
            "sha256_hash": model_hash,
            "created_at": time.time(),
            "metadata": metadata
        }

        meta_path = os.path.join(MODELS_DIR, f"{model_name}_v{version}_meta.json")
        with open(meta_path, 'w') as f:
            json.dump(meta, f, indent=2)

        return file_path

    @classmethod
    def load_model(cls, model_name: str, version: str) -> tuple[Any, Dict[str, Any]]:
        """
        Loads a model artifact and verifies its SHA-256 checksum.
        """
        filename = f"{model_name}_v{version}.pkl"
        file_path = os.path.join(MODELS_DIR, filename)
        meta_path = os.path.join(MODELS_DIR, f"{model_name}_v{version}_meta.json")

        if not os.path.exists(file_path) or not os.path.exists(meta_path):
            raise FileNotFoundError(f"Model version {version} for {model_name} not found.")

        with open(meta_path, 'r') as f:
            meta = json.load(f)

        current_hash = cls._compute_sha256(file_path)
        if current_hash != meta["sha256_hash"]:
            raise ValueError(f"Model checksum mismatch for {filename}! File may be corrupted or tampered.")

        with open(file_path, 'rb') as f:
            model_obj = pickle.load(f)

        return model_obj, meta

    @classmethod
    def list_models(cls) -> list[Dict[str, Any]]:
        """
        Lists all registered model versions and their metadata.
        """
        models = []
        if not os.path.exists(MODELS_DIR):
            return models

        for fname in os.listdir(MODELS_DIR):
            if fname.endswith("_meta.json"):
                with open(os.path.join(MODELS_DIR, fname), 'r') as f:
                    models.append(json.load(f))
        return models
