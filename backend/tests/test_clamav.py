import pytest
import io
from fastapi.testclient import TestClient
from app.services.clamav_scanner import ClamAVScanner, clamav_service
from app.services.clamd_daemon import EICAR_STANDARD_STRING, EICAR_SIG_NAME

def test_clamav_unavailable_graceful_handling():
    # Scanner pointing to a non-existent port
    scanner = ClamAVScanner(host="127.0.0.1", port=59999, timeout=0.2)
    result = scanner.scan_stream(b"MZ" + b"\x00" * 100)
    assert result.status == "unavailable"
    assert result.available is False
    assert result.matched is False
    assert result.signature_name is None
    assert "unavailable" in result.message.lower()

def test_official_clamav_daemon_connection_and_identity():
    """Confirms FastAPI connects to the official ClamAV daemon in WSL2, not the dev emulator."""
    is_online, is_official, ver_str = clamav_service.verify_daemon_engine(timeout=1.0)
    assert is_online is True, "ClamAV daemon must be reachable on port 3310"
    assert is_official is True, f"Expected official ClamAV daemon, got: {ver_str}"
    assert ver_str.startswith("ClamAV "), f"Expected version to start with 'ClamAV ', got: {ver_str}"
    assert "emulator" not in ver_str.lower(), "Must NOT be using Python development emulator"
    assert "dev-only" not in ver_str.lower(), "Must NOT be dev-only test daemon"

def test_official_clamav_eicar_signature_detection():
    """Asserts that official ClamAV returns 'Eicar-Test-Signature' and backend flags as official match."""
    result = clamav_service.scan_stream(EICAR_STANDARD_STRING)
    assert result.status == "infected"
    assert result.available is True
    assert result.matched is True
    assert result.is_emulator is False, "Official ClamAV must have is_emulator=False"
    assert result.signature_name == "Eicar-Test-Signature"
    assert "Official ClamAV signature match detected: Eicar-Test-Signature" in result.message

def test_official_clamav_clean_stream():
    """Asserts that clean binary streams are reported as clean with official ClamAV verification."""
    result = clamav_service.scan_stream(b"Safe binary payload with no threat markers")
    assert result.status == "clean"
    assert result.available is True
    assert result.matched is False
    assert result.signature_name is None
    assert result.is_emulator is False
    assert "Official ClamAV scan completed" in result.message

def test_eicar_test_endpoint_with_official_clamav(auth_client: TestClient):
    """Verifies that the /api/v1/scans/test-eicar endpoint safely scans EICAR via official ClamAV."""
    response = auth_client.post("/api/v1/scans/test-eicar")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert "EICAR" in data["tested_signature"]
    
    clamav_res = data["clamav_result"]
    assert clamav_res["status"] == "infected"
    assert clamav_res["matched"] is True
    assert clamav_res["is_emulator"] is False
    assert clamav_res["signature_name"] == "Eicar-Test-Signature"

def test_clean_pe_scan_produces_no_threat_detected_verdict(auth_client: TestClient, valid_pe_bytes: bytes):
    """Verifies clean PE file upload produces NO_THREAT_DETECTED when official ClamAV and ML are benign."""
    files = {"file": ("clean_sample.exe", io.BytesIO(valid_pe_bytes), "application/x-dosexec")}
    response = auth_client.post("/api/v1/scans", files=files)
    assert response.status_code == 201
    data = response.json()
    
    # Official ClamAV must report clean and not emulator
    assert data["clamav"]["available"] is True
    assert data["clamav"]["status"] == "clean"
    assert data["clamav"]["matched"] is False
    assert data["clamav"]["is_emulator"] is False
    
    # ML model must predict benign
    assert data["ml_inference"]["available"] is True
    assert data["ml_inference"]["prediction"] == "benign"
    
    # Conservative synthesis must award definitive NO_THREAT_DETECTED
    assert data["verdict"] == "NO_THREAT_DETECTED"
    assert any("No signature matches in official ClamAV" in r for r in data["verdict_reasons"])

