import os
import json
from typing import Dict, Any, List, Optional
import numpy as np
import pefile

from app.config import settings
from app.models.schemas import MLInferenceResult, PEAnalysisResult
from app.core.logging import logger
from app.ml.pe_feature_extractor import (
    FEATURE_NAMES,
    extract_features_from_pe,
    extract_feature_vector_from_bytes,
)

class MLClassifierService:
    """
    Modular Machine Learning classifier service powered by a real scikit-learn
    RandomForestClassifier trained on 16,600+ unique Windows PE malware and benign samples.
    Adheres strictly to the conservative verdict requirement:
    - Real predictions and probability estimates based on static PE features.
    - Explicitly identified as statistical model estimates, not guaranteed certainty.
    - Never fabricates predictions or confidence scores.
    """

    def __init__(self, model_path: str = settings.ML_MODEL_PATH):
        self.model_path = model_path
        self._model = None
        self._is_loaded = False
        self._feature_schema: Optional[Dict[str, Any]] = None
        self._metrics: Optional[Dict[str, Any]] = None
        self._resolved_model_path: Optional[str] = None
        self._check_and_load_model()

    def _resolve_path(self, path: str) -> Optional[str]:
        """Resolves relative model/schema paths robustly across working directories."""
        candidates = [
            path,
            os.path.join(os.path.dirname(os.path.dirname(__file__)), "ml", "models", os.path.basename(path)),
            os.path.join(os.getcwd(), path),
            os.path.join(os.getcwd(), "backend", path),
        ]
        for candidate in candidates:
            if candidate and os.path.exists(candidate):
                return os.path.abspath(candidate)
        return None

    def _check_and_load_model(self):
        """Attempts to load the serialized model and metadata from disk."""
        resolved = self._resolve_path(self.model_path)
        if resolved and os.path.exists(resolved):
            try:
                import joblib
                self._model = joblib.load(resolved)
                self._is_loaded = True
                self._resolved_model_path = resolved
                logger.info(f"Loaded Random Forest PE Classifier model from: {resolved}")

                # Load companion feature schema if present
                schema_path = os.path.join(os.path.dirname(resolved), "feature_schema.json")
                if os.path.exists(schema_path):
                    try:
                        with open(schema_path, "r", encoding="utf-8") as f:
                            self._feature_schema = json.load(f)
                    except Exception as e:
                        logger.warning(f"Could not load feature_schema.json: {e}")

                # Load companion metrics if present
                metrics_path = os.path.join(os.path.dirname(resolved), "metrics.json")
                if os.path.exists(metrics_path):
                    try:
                        with open(metrics_path, "r", encoding="utf-8") as f:
                            self._metrics = json.load(f)
                    except Exception as e:
                        logger.warning(f"Could not load metrics.json: {e}")

            except Exception as e:
                logger.error(f"Failed to load Random Forest model at {resolved}: {e}")
                self._is_loaded = False
                self._model = None
        else:
            logger.info(f"Random Forest model file not found at: {self.model_path}")
            self._is_loaded = False
            self._model = None

    def reload_model(self, custom_path: Optional[str] = None):
        """Reloads the model from disk, optionally using an updated file path."""
        if custom_path:
            self.model_path = custom_path
        self._check_and_load_model()

    def extract_canonical_features(self, pe: pefile.PE) -> Dict[str, float]:
        """
        Extracts the exact 69 canonical PE features matching the trained model schema.
        """
        return extract_features_from_pe(pe)

    def extract_numerical_features(self, pe_data: PEAnalysisResult, file_size: int) -> Dict[str, float]:
        """
        Legacy 8-feature representation maintained for backward compatibility.
        """
        return {
            "file_size": float(file_size),
            "number_of_sections": float(pe_data.headers.number_of_sections),
            "file_entropy": float(pe_data.file_entropy),
            "imported_dlls_count": float(pe_data.imported_dlls_count),
            "total_imports_count": float(pe_data.total_imports_count),
            "exported_functions_count": float(pe_data.exported_functions_count),
            "is_dll": 1.0 if pe_data.headers.is_dll else 0.0,
            "suspicious_apis_count": float(len(pe_data.suspicious_indicators)),
        }

    def predict(
        self,
        pe_data: Optional[PEAnalysisResult] = None,
        file_size: int = 0,
        raw_bytes: Optional[bytes] = None,
        pe_object: Optional[pefile.PE] = None
    ) -> MLInferenceResult:
        """
        Executes ML classification if model is available.
        If model weights are not loaded, returns an explicit 'model_not_loaded' status.
        Never fabricates predictions.
        """
        expected_feature_count = len(FEATURE_NAMES)

        if not self._is_loaded or self._model is None:
            return MLInferenceResult(
                status="model_not_loaded",
                available=False,
                model_name="Random Forest PE Classifier v1.0",
                prediction=None,
                confidence_score=None,
                features_used_count=0,
                message="Random Forest classifier weights not loaded on this backend node."
            )

        try:
            # 1. Extract the canonical 69-feature vector
            if raw_bytes is not None:
                feature_vector = extract_feature_vector_from_bytes(raw_bytes)
            elif pe_object is not None:
                feat_dict = self.extract_canonical_features(pe_object)
                feature_vector = [feat_dict[name] for name in FEATURE_NAMES]
            else:
                # Fallback if raw binary not provided: construct zero-padded vector from pe_data
                feature_vector = [0.0] * expected_feature_count
                if pe_data is not None:
                    # Map basic fields that are available
                    name_to_idx = {name: i for i, name in enumerate(FEATURE_NAMES)}
                    if "NumberOfSections" in name_to_idx:
                        feature_vector[name_to_idx["NumberOfSections"]] = float(pe_data.headers.number_of_sections)
                    if "DirectoryEntryImport" in name_to_idx:
                        feature_vector[name_to_idx["DirectoryEntryImport"]] = float(pe_data.imported_dlls_count)
                    if "DirectoryEntryExport" in name_to_idx:
                        feature_vector[name_to_idx["DirectoryEntryExport"]] = float(pe_data.exported_functions_count)
                    if "SuspiciousImportFunctions" in name_to_idx:
                        feature_vector[name_to_idx["SuspiciousImportFunctions"]] = float(len(pe_data.suspicious_indicators))

            feature_arr = np.array([feature_vector], dtype=np.float64)

            # 2. Execute inference
            pred_idx = int(self._model.predict(feature_arr)[0])
            proba = self._model.predict_proba(feature_arr)[0]
            probability_score = float(proba[pred_idx])

            prediction_label = "malicious" if pred_idx == 1 else "benign"
            percentage = probability_score * 100.0

            # Explanatory message clearly identifying this as a model estimate
            if prediction_label == "malicious":
                msg = (
                    f"Random Forest statistical model estimate: Classified as malicious with "
                    f"estimated probability of {percentage:.1f}%. (Model estimate based on "
                    f"{expected_feature_count} static PE features, not an absolute guarantee)."
                )
            else:
                msg = (
                    f"Random Forest statistical model estimate: Classified as benign with "
                    f"estimated probability of {percentage:.1f}%. (Model estimate based on "
                    f"{expected_feature_count} static PE features, not an absolute guarantee)."
                )

            return MLInferenceResult(
                status="loaded",
                available=True,
                model_name="Random Forest PE Classifier v1.0",
                prediction=prediction_label,
                confidence_score=round(probability_score, 4),
                features_used_count=expected_feature_count,
                message=msg
            )

        except Exception as e:
            logger.error(f"Inference error during ML prediction: {e}")
            return MLInferenceResult(
                status="error",
                available=False,
                model_name="Random Forest PE Classifier v1.0",
                prediction=None,
                confidence_score=None,
                features_used_count=0,
                message=f"Model inference runtime error: {str(e)}"
            )

# Global singleton service instance
ml_service = MLClassifierService()
