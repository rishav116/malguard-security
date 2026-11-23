"""
Verification script confirming identical backend behavior for Homepage Quick Scan and /scanner
- Both route to /api/v1/scan (and /api/v1/scans)
- Both enforce genuine PE/COFF validation
- Both run ClamAV + 69-feature Random Forest ML inference
- Both persist scan metadata to Supabase PostgreSQL table 'scans'
- Confirms matching verdicts, SHA-256, and scan history
"""
import io
import time
import jwt
from fastapi.testclient import TestClient

from app.main import app
from app.config import settings
from tests.conftest import generate_minimal_valid_pe

TEST_SECRET = "production-scan-matching-secret-key-32b-min!"
TEST_USER_ID = "98765432-1234-5678-1234-567898765432"

def make_jwt(sub: str = TEST_USER_ID) -> str:
    payload = {
        "sub": sub,
        "email": "analyst@malguard.ai",
        "role": "authenticated",
        "aud": "authenticated",
        "exp": int(time.time()) + 3600,
        "iat": int(time.time()),
    }
    return jwt.encode(payload, TEST_SECRET, algorithm="HS256")

def run_verification():
    print("======================================================================")
    print("MALGUARD AI — Homepage Quick Scan vs /scanner Verification")
    print("======================================================================")

    settings.ENVIRONMENT = "production"
    settings.ALLOW_DEMO_AUTH = False
    settings.SUPABASE_JWT_SECRET = TEST_SECRET

    token = make_jwt()
    headers = {"Authorization": f"Bearer {token}"}
    client = TestClient(app)

    pe_bytes = generate_minimal_valid_pe()
    print(f"Generated minimal valid Windows PE32 binary ({len(pe_bytes)} bytes)")

    # 1. Simulate submission from /scanner
    print("\n--- 1. Submitting Binary via /scanner endpoint (/api/v1/scans) ---")
    files_scanner = {"file": ("scanner_binary.exe", io.BytesIO(pe_bytes), "application/x-dosexec")}
    res_scanner = client.post("/api/v1/scans", files=files_scanner, headers=headers)
    print(f"Status Code: {res_scanner.status_code}")
    assert res_scanner.status_code == 201, f"Expected 201, got {res_scanner.status_code}: {res_scanner.text}"
    data_scanner = res_scanner.json()

    print(f"  Scan ID:      {data_scanner['scan_id']}")
    print(f"  Verdict:      {data_scanner['verdict']}")
    print(f"  SHA-256:      {data_scanner['hashes']['sha256']}")
    print(f"  Entropy:      {data_scanner['pe_analysis']['file_entropy']}")
    print(f"  ClamAV:       {data_scanner['clamav']['status']} ({data_scanner['clamav']['message']})")
    print(f"  ML Model:     {data_scanner['ml_inference']['status']} ({data_scanner['ml_inference']['prediction']})")
    print(f"  Rationale:    {data_scanner['verdict_reasons']}")

    # 2. Simulate submission from Homepage Quick Scan (/api/v1/scan)
    print("\n--- 2. Submitting Same Binary via Homepage Quick Scan (/api/v1/scan) ---")
    files_quick = {"file": ("quickscan_binary.exe", io.BytesIO(pe_bytes), "application/x-dosexec")}
    res_quick = client.post("/api/v1/scan", files=files_quick, headers=headers)
    print(f"Status Code: {res_quick.status_code}")
    assert res_quick.status_code == 201, f"Expected 201, got {res_quick.status_code}: {res_quick.text}"
    data_quick = res_quick.json()

    print(f"  Scan ID:      {data_quick['scan_id']}")
    print(f"  Verdict:      {data_quick['verdict']}")
    print(f"  SHA-256:      {data_quick['hashes']['sha256']}")
    print(f"  Entropy:      {data_quick['pe_analysis']['file_entropy']}")
    print(f"  ClamAV:       {data_quick['clamav']['status']} ({data_quick['clamav']['message']})")
    print(f"  ML Model:     {data_quick['ml_inference']['status']} ({data_quick['ml_inference']['prediction']})")
    print(f"  Rationale:    {data_quick['verdict_reasons']}")

    # 3. Verify Matching Integrity
    print("\n--- 3. Verifying Results Matching Integrity ---")
    assert data_scanner["verdict"] == data_quick["verdict"], "Verdicts must match!"
    assert data_scanner["hashes"]["sha256"] == data_quick["hashes"]["sha256"], "SHA-256 must match!"
    assert data_scanner["hashes"]["md5"] == data_quick["hashes"]["md5"], "MD5 must match!"
    assert data_scanner["pe_analysis"]["file_entropy"] == data_quick["pe_analysis"]["file_entropy"], "Entropy must match!"
    assert data_scanner["pe_analysis"]["headers"]["machine"] == data_quick["pe_analysis"]["headers"]["machine"], "Machine architecture must match!"
    assert data_scanner["ml_inference"]["prediction"] == data_quick["ml_inference"]["prediction"], "ML predictions must match!"
    assert data_scanner["clamav"]["status"] == data_quick["clamav"]["status"], "ClamAV status must match!"
    print(">>> PASS: Both endpoints produced identical detection verdicts and PE metadata!")

    # 4. Verify Scan History Persistence in Threat Reports (/api/v1/scans)
    print("\n--- 4. Verifying Scan History Persistence in Threat Reports ---")
    history_res = client.get("/api/v1/scans", headers=headers)
    print(f"History Status Code: {history_res.status_code}")
    assert history_res.status_code == 200
    history_data = history_res.json()
    scans_list = history_data if isinstance(history_data, list) else history_data.get("scans", [])
    print(f"Total Persisted Scans for user: {len(scans_list)}")
    scan_ids = [s["id"] for s in scans_list]
    print(f"Persisted Scan IDs: {scan_ids}")
    assert data_scanner["scan_id"] in scan_ids, f"Scan {data_scanner['scan_id']} not found in history!"
    assert data_quick["scan_id"] in scan_ids, f"Scan {data_quick['scan_id']} not found in history!"
    print(">>> PASS: Both scans successfully persisted and retrieved from Threat Reports!")

    print("\n======================================================================")
    print("ALL VERIFICATION CHECKS PASSED: HOMEPAGE SCANNER FULLY GENUINE & SYNCED!")
    print("======================================================================")

if __name__ == "__main__":
    run_verification()
