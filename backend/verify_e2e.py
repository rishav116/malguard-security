"""
End-to-End Verification Script for Malix AI Assistant Authentication Fix
Simulates exact production behavior:
- ENVIRONMENT = "production"
- ALLOW_DEMO_AUTH = False
- Supabase HS256 JWT signature verification
- Missing token, Expired token, Demo token, Valid token
- Case-insensitivity for reverse proxy headers (Next.js / Vercel)
- Streaming SSE endpoint validation
"""
import sys
import time
import jwt
from unittest.mock import MagicMock, AsyncMock, patch
from fastapi.testclient import TestClient

from app.main import app
from app.config import settings

TEST_SECRET = "production-super-secret-key-that-is-at-least-32-chars-long!"
TEST_USER_ID = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"

def make_jwt(sub: str = TEST_USER_ID, exp_offset: int = 3600) -> str:
    payload = {
        "sub": sub,
        "email": "security-analyst@malguard.ai",
        "role": "authenticated",
        "aud": "authenticated",
        "exp": int(time.time()) + exp_offset,
        "iat": int(time.time()),
    }
    return jwt.encode(payload, TEST_SECRET, algorithm="HS256")

def run_e2e_verification():
    print("======================================================================")
    print("MALGUARD AI — Production Malix AI Assistant E2E Authentication Verification")
    print("======================================================================")

    # 1. Configure strict production settings
    settings.ENVIRONMENT = "production"
    settings.ALLOW_DEMO_AUTH = False
    settings.SUPABASE_JWT_SECRET = TEST_SECRET

    client = TestClient(app)

    print(f"\n[Environment Configuration]")
    print(f"  ENVIRONMENT          = {settings.ENVIRONMENT}")
    print(f"  ALLOW_DEMO_AUTH      = {settings.ALLOW_DEMO_AUTH}")
    print(f"  SUPABASE_JWT_SECRET  = [CONFIGURED - {len(TEST_SECRET)} bytes]")
    print(f"  SUPABASE_URL         = {settings.SUPABASE_URL}")

    # TEST 1: Unauthenticated request without Authorization header
    print("\n--- TEST 1: Request WITHOUT Authorization Header in Production ---")
    res1 = client.post("/api/v1/copilot/chat", json={"message": "Analyze sample entropy"})
    print(f"  Status Code: {res1.status_code}")
    print(f"  Response Detail: {res1.json().get('detail')}")
    assert res1.status_code == 401, f"Expected 401, got {res1.status_code}"
    assert "Missing Authorization header with Bearer token." in res1.json()["detail"]
    print("  >>> PASS: Correctly rejected with 401 and 'Missing Authorization header' message.")

    # TEST 2: Request with expired JWT token
    print("\n--- TEST 2: Request WITH Expired JWT Bearer Token in Production ---")
    expired_token = make_jwt(exp_offset=-1800)
    res2 = client.post(
        "/api/v1/copilot/chat",
        headers={"Authorization": f"Bearer {expired_token}"},
        json={"message": "Analyze sample entropy"}
    )
    print(f"  Status Code: {res2.status_code}")
    print(f"  Response Detail: {res2.json().get('detail')}")
    assert res2.status_code == 401, f"Expected 401, got {res2.status_code}"
    print("  >>> PASS: Correctly rejected expired token with HTTP 401.")

    # TEST 3: Request with demo token in production
    print("\n--- TEST 3: Request WITH Demo Token in Production ---")
    res3 = client.post(
        "/api/v1/copilot/chat",
        headers={"Authorization": "Bearer demo-token"},
        json={"message": "Analyze sample entropy"}
    )
    print(f"  Status Code: {res3.status_code}")
    print(f"  Response Detail: {res3.json().get('detail')}")
    assert res3.status_code == 401, f"Expected 401, got {res3.status_code}"
    assert "Demo authentication tokens are disabled in production" in res3.json()["detail"]
    print("  >>> PASS: Demo token strictly rejected in production mode.")

    # TEST 4: Valid Authenticated Request to /chat
    print("\n--- TEST 4: Request WITH Valid Signed Supabase Bearer Token (Non-streaming) ---")
    valid_token = make_jwt()
    with patch("google.genai.models.AsyncModels.generate_content", new_callable=AsyncMock) as mock_gemini:
        mock_resp = MagicMock()
        mock_resp.text = "MALGUARD AI Analysis: Shannon entropy 6.2 indicates normal uncompressed code sections."
        mock_gemini.return_value = mock_resp

        res4 = client.post(
            "/api/v1/copilot/chat",
            headers={"Authorization": f"Bearer {valid_token}"},
            json={"message": "Explain section entropy", "history": []}
        )
        print(f"  Status Code: {res4.status_code}")
        assert res4.status_code == 200, f"Expected 200, got {res4.status_code}: {res4.text}"
        data4 = res4.json()
        print(f"  Model Used: {data4.get('model_used')}")
        print(f"  Assistant Reply: {data4.get('reply')[:70]}...")
        assert "Shannon entropy 6.2" in data4["reply"]
        print("  >>> PASS: Authenticated request accepted and handled successfully!")

    # TEST 5: Valid Authenticated Request with Lowercase Header (Reverse Proxy / Next.js)
    print("\n--- TEST 5: Authenticated Request with Lowercase 'authorization' Header ---")
    with patch("google.genai.models.AsyncModels.generate_content", new_callable=AsyncMock) as mock_gemini:
        mock_resp = MagicMock()
        mock_resp.text = "Proxy header normalization test passed."
        mock_gemini.return_value = mock_resp

        res5 = client.post(
            "/api/v1/copilot/chat",
            headers={"authorization": f"bearer {valid_token}"},
            json={"message": "Test proxy casing", "history": []}
        )
        print(f"  Status Code: {res5.status_code}")
        assert res5.status_code == 200, f"Expected 200, got {res5.status_code}"
        print("  >>> PASS: Reverse proxy lowercase header casing accepted.")

    # TEST 6: Authenticated Real-Time Streaming SSE Request
    print("\n--- TEST 6: Authenticated Streaming Request (/chat/stream) ---")
    with patch("google.genai.models.AsyncModels.generate_content_stream") as mock_stream:
        async def fake_stream_generator(*args, **kwargs):
            chunks = ["Analyzing ", "PE ", "binary ", "structure..."]
            for c in chunks:
                m = MagicMock()
                m.text = c
                yield m

        mock_stream.side_effect = fake_stream_generator

        res6 = client.post(
            "/api/v1/copilot/chat/stream",
            headers={"Authorization": f"Bearer {valid_token}"},
            json={"message": "Stream analysis", "history": []}
        )
        print(f"  Status Code: {res6.status_code}")
        print(f"  Content-Type: {res6.headers.get('content-type')}")
        assert res6.status_code == 200, f"Expected 200, got {res6.status_code}"
        assert "text/event-stream" in res6.headers.get("content-type", "")
        assert "data: " in res6.text
        print(f"  Sample SSE Stream Output (First 120 bytes): {res6.text[:120].strip()}")
        print("  >>> PASS: Streaming SSE endpoint authenticated and stream delivered successfully!")

    print("\n======================================================================")
    print("ALL 6 END-TO-END VERIFICATION CHECKS COMPLETED AND PASSED PERFECTLY!")
    print("======================================================================")

if __name__ == "__main__":
    run_e2e_verification()
