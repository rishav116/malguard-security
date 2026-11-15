import os
import json
import pefile
import pytest
from app.services.ml_classifier import MLClassifierService, ml_service
from app.services.pe_analyzer import analyze_pe_binary
from app.ml.pe_feature_extractor import (
    FEATURE_NAMES,
    FEATURE_CATEGORIES,
    extract_features_from_pe,
    extract_feature_vector_from_bytes,
)

def test_ml_service_model_not_loaded(valid_pe_bytes: bytes):
    """Test fallback when model path does not exist."""
    service = MLClassifierService(model_path="nonexistent_model.pkl")
    pe_data = analyze_pe_binary(valid_pe_bytes)
    result = service.predict(pe_data, len(valid_pe_bytes))
    
    assert result.status == "model_not_loaded"
    assert result.available is False
    assert result.prediction is None
    assert result.confidence_score is None
    assert "not loaded" in result.message

def test_ml_service_model_loaded():
    """Verify that the real trained model is loaded on the singleton service."""
    assert ml_service._is_loaded is True
    assert ml_service._model is not None
    assert hasattr(ml_service._model, "predict")
    assert hasattr(ml_service._model, "predict_proba")
    assert ml_service._model.n_features_in_ == 69

def test_feature_names_order_and_count():
    """Verify exact count and ordering of the 69 canonical PE features."""
    assert len(FEATURE_NAMES) == 69
    assert FEATURE_NAMES[0] == "e_cblp"
    assert FEATURE_NAMES[16] == "Machine"
    assert FEATURE_NAMES[17] == "NumberOfSections"
    assert FEATURE_NAMES[51] == "SuspiciousImportFunctions"
    assert FEATURE_NAMES[68] == "ImageDirectoryEntrySecurity"

def test_feature_category_counts():
    """Verify exact, mutually exclusive category counts summing to 69."""
    assert len(FEATURE_CATEGORIES["dos_header"]) == 16
    assert len(FEATURE_CATEGORIES["coff_file_header"]) == 7
    assert len(FEATURE_CATEGORIES["optional_header"]) == 28
    assert len(FEATURE_CATEGORIES["section_metrics"]) == 9
    assert len(FEATURE_CATEGORIES["import_table_apis"]) == 3
    assert len(FEATURE_CATEGORIES["export_table_directories"]) == 6

    total = sum(len(feats) for feats in FEATURE_CATEGORIES.values())
    assert total == 69

    # Verify every feature belongs to exactly one category
    flattened = [f for feats in FEATURE_CATEGORIES.values() for f in feats]
    assert len(flattened) == len(set(flattened)) == 69
    assert set(flattened) == set(FEATURE_NAMES)

def test_canonical_feature_extraction(valid_pe_bytes: bytes):
    """Verify feature extractor extracts all 69 features in exact key order."""
    pe = pefile.PE(data=valid_pe_bytes)
    try:
        feat_dict = extract_features_from_pe(pe)
        assert list(feat_dict.keys()) == FEATURE_NAMES
    finally:
        pe.close()

    vector = extract_feature_vector_from_bytes(valid_pe_bytes)
    assert len(vector) == 69
    assert all(isinstance(v, (int, float)) for v in vector)
    assert all(not (v != v) for v in vector)  # Check no NaN

def test_real_pe_prediction(valid_pe_bytes: bytes):
    """Verify inference on valid PE bytes produces real prediction and probability."""
    pe_data = analyze_pe_binary(valid_pe_bytes)
    result = ml_service.predict(pe_data=pe_data, file_size=len(valid_pe_bytes), raw_bytes=valid_pe_bytes)

    assert result.status == "loaded"
    assert result.available is True
    assert result.prediction in ("malicious", "benign")
    assert result.confidence_score is not None
    assert 0.0 <= result.confidence_score <= 1.0
    assert result.features_used_count == 69
    assert "estimate" in result.message.lower()

def test_feature_schema_matches_model():
    """Verify saved feature_schema.json matches model feature dimension and names."""
    schema_path = os.path.join(
        os.path.dirname(os.path.dirname(__file__)),
        "app", "ml", "models", "feature_schema.json"
    )
    assert os.path.exists(schema_path), f"Schema file not found at {schema_path}"
    with open(schema_path, "r", encoding="utf-8") as f:
        schema = json.load(f)
    
    assert schema["feature_count"] == 69
    assert schema["feature_names"] == FEATURE_NAMES
    assert schema["target_mapping"] == {"0": "benign", "1": "malicious"}
    assert schema["category_counts"]["dos_header"] == 16
    assert schema["category_counts"]["coff_file_header"] == 7
    assert schema["category_counts"]["optional_header"] == 28
    assert schema["category_counts"]["section_metrics"] == 9
    assert schema["category_counts"]["import_table_apis"] == 3
    assert schema["category_counts"]["export_table_directories"] == 6

def test_metrics_json_integrity():
    """Verify metrics.json contains valid evaluation results."""
    metrics_path = os.path.join(
        os.path.dirname(os.path.dirname(__file__)),
        "app", "ml", "models", "metrics.json"
    )
    assert os.path.exists(metrics_path), f"Metrics file not found at {metrics_path}"
    with open(metrics_path, "r", encoding="utf-8") as f:
        metrics = json.load(f)

    eval_m = metrics["evaluation_metrics"]
    assert eval_m["accuracy"] >= 0.95, f"Expected accuracy >= 0.95, got {eval_m['accuracy']}"
    assert eval_m["roc_auc"] >= 0.98, f"Expected roc_auc >= 0.98, got {eval_m['roc_auc']}"
    assert "confusion_matrix" in eval_m
    assert len(metrics["top_features"]) >= 10

def test_corrupted_model_file_fallback(tmp_path):
    """Verify graceful handling when model file is corrupted."""
    bad_model = tmp_path / "corrupted.pkl"
    bad_model.write_text("NOT A VALID PICKLE FILE")
    
    service = MLClassifierService(model_path=str(bad_model))
    assert service._is_loaded is False
    assert service._model is None
