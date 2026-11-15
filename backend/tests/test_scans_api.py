import io
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.core.auth import get_current_user, UserIdentity

def test_scan_requires_authentication(client: TestClient, valid_pe_bytes: bytes):
    files = {"file": ("test.exe", io.BytesIO(valid_pe_bytes), "application/x-dosexec")}
    response = client.post("/api/v1/scans", files=files)
    assert response.status_code == 401
    assert "Missing Authorization" in response.json()["detail"]

def test_scan_rejects_demo_token_when_disabled(client: TestClient, valid_pe_bytes: bytes):
    # When ALLOW_DEMO_AUTH is False, sending demo-token must return 401
    files = {"file": ("test.exe", io.BytesIO(valid_pe_bytes), "application/x-dosexec")}
    headers = {"Authorization": "Bearer demo-token"}
    response = client.post("/api/v1/scans", files=files, headers=headers)
    assert response.status_code in [401, 503]

def test_scan_rejects_non_exe_extension(auth_client: TestClient):
    files = {"file": ("malicious_doc.pdf", io.BytesIO(b"PDF-1.4 Fake PDF"), "application/pdf")}
    response = auth_client.post("/api/v1/scans", files=files)
    assert response.status_code == 400
    assert "Unsupported file format" in response.json()["detail"]

def test_scan_rejects_corrupted_pe(auth_client: TestClient):
    fake_exe_bytes = b"MZ" + b"Corrupted body without PE header" * 10
    files = {"file": ("corrupted.exe", io.BytesIO(fake_exe_bytes), "application/x-dosexec")}
    response = auth_client.post("/api/v1/scans", files=files)
    assert response.status_code == 400

def test_scan_rejects_oversized_file(auth_client: TestClient):
    # 11 MB binary exceeds 10 MB limit
    oversized_bytes = b"MZ" + b"\x00" * (11 * 1024 * 1024)
    files = {"file": ("oversized.exe", io.BytesIO(oversized_bytes), "application/x-dosexec")}
    response = auth_client.post("/api/v1/scans", files=files)
    assert response.status_code == 413
    assert "File exceeds maximum allowed size" in response.json()["detail"]

def test_scan_successful_with_valid_pe(auth_client: TestClient, valid_pe_bytes: bytes):
    files = {"file": ("sample.exe", io.BytesIO(valid_pe_bytes), "application/x-dosexec")}
    response = auth_client.post("/api/v1/scans", files=files)
    assert response.status_code == 201
    data = response.json()
    
    # Verify core fields
    assert "scan_id" in data
    assert data["file_name"] == "sample.exe"
    assert data["owner_id"] == "test-analyst-uuid-999"
    assert "hashes" in data
    assert len(data["hashes"]["sha256"]) == 64
    
    # Verify PE analysis
    assert "pe_analysis" in data
    assert data["pe_analysis"]["status"] == "success"
    assert "headers" in data["pe_analysis"]
    assert len(data["pe_analysis"]["sections"]) >= 1
    
    # Verify ClamAV & ML Engine states
    assert "clamav" in data
    assert "ml_inference" in data
    assert data["verdict"] in ("NO_THREAT_DETECTED", "INCONCLUSIVE", "SUSPICIOUS", "MALICIOUS")

def test_list_scans_history_and_persistence(auth_client: TestClient, valid_pe_bytes: bytes):
    # 1. Post a scan
    files = {"file": ("persistent_artifact.exe", io.BytesIO(valid_pe_bytes), "application/x-dosexec")}
    create_resp = auth_client.post("/api/v1/scans", files=files)
    assert create_resp.status_code == 201
    scan_id = create_resp.json()["scan_id"]

    # 2. Query scan history
    hist_resp = auth_client.get("/api/v1/scans")
    assert hist_resp.status_code == 200
    scans = hist_resp.json()
    assert isinstance(scans, list)
    assert any(s["id"] == scan_id for s in scans)

    # 3. Query specific scan detail
    detail_resp = auth_client.get(f"/api/v1/scans/{scan_id}")
    assert detail_resp.status_code == 200
    detail = detail_resp.json()
    assert detail["id"] == scan_id
    assert detail["file_name"] == "persistent_artifact.exe"

def test_dashboard_metrics_endpoint(auth_client: TestClient):
    response = auth_client.get("/api/v1/scans/dashboard/metrics")
    assert response.status_code == 200
    data = response.json()
    assert "total_scans" in data
    assert "threats_detected" in data
    assert "clean_files" in data
    assert "suspicious_files" in data
    assert "recent_scans" in data
    assert "threat_distribution" in data

def test_tenant_access_control_isolation(client: TestClient, valid_pe_bytes: bytes):
    # User 1 creates a scan
    user1 = UserIdentity(user_id="user-tenant-1", email="user1@org.com")
    app.dependency_overrides[get_current_user] = lambda: user1

    files = {"file": ("confidential_user1.exe", io.BytesIO(valid_pe_bytes), "application/x-dosexec")}
    create_resp = client.post("/api/v1/scans", files=files)
    assert create_resp.status_code == 201
    user1_scan_id = create_resp.json()["scan_id"]

    # Switch to User 2
    user2 = UserIdentity(user_id="user-tenant-2", email="user2@other.com")
    app.dependency_overrides[get_current_user] = lambda: user2

    # User 2 queries their scan list -> must NOT see user 1's scan
    u2_scans_resp = client.get("/api/v1/scans")
    assert u2_scans_resp.status_code == 200
    u2_scans = u2_scans_resp.json()
    assert all(s["id"] != user1_scan_id for s in u2_scans)

    # User 2 attempts direct access to User 1's scan_id -> MUST return 404
    u2_detail_resp = client.get(f"/api/v1/scans/{user1_scan_id}")
    assert u2_detail_resp.status_code == 404

    # Clean up override
    app.dependency_overrides.clear()
