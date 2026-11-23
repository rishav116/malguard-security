import time
import json
import jwt
import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from fastapi.testclient import TestClient
from app.main import app
from app.config import settings

TEST_JWT_SECRET = "test-secret-key-super-secure-32-bytes-minimum!"

def generate_test_jwt(user_id: str = "analyst-test-uuid-456", exp_offset: int = 3600) -> str:
    """Generates a test Supabase-compliant HS256 JWT token."""
    payload = {
        "sub": user_id,
        "email": "analyst@malguard.ai",
        "role": "authenticated",
        "aud": "authenticated",
        "exp": int(time.time()) + exp_offset,
        "iat": int(time.time()),
    }
    return jwt.encode(payload, TEST_JWT_SECRET, algorithm="HS256")

@pytest.fixture
def prod_env():
    """Forces production mode with demo auth disabled."""
    orig_env = settings.ENVIRONMENT
    orig_demo = settings.ALLOW_DEMO_AUTH
    orig_secret = settings.SUPABASE_JWT_SECRET

    settings.ENVIRONMENT = "production"
    settings.ALLOW_DEMO_AUTH = False
    settings.SUPABASE_JWT_SECRET = TEST_JWT_SECRET

    yield

    settings.ENVIRONMENT = orig_env
    settings.ALLOW_DEMO_AUTH = orig_demo
    settings.SUPABASE_JWT_SECRET = orig_secret

def test_chat_missing_authorization_header_rejected(client: TestClient, prod_env):
    """Verifies that requests without Authorization header are strictly rejected in production with HTTP 401."""
    response = client.post("/api/v1/copilot/chat", json={"message": "Is this binary malicious?"})
    assert response.status_code == 401
    assert "Missing Authorization header with Bearer token." in response.json()["detail"]

def test_stream_missing_authorization_header_rejected(client: TestClient, prod_env):
    """Verifies that streaming requests without Authorization header are rejected in production with HTTP 401."""
    response = client.post("/api/v1/copilot/chat/stream", json={"message": "Is this binary malicious?"})
    assert response.status_code == 401
    assert "Missing Authorization header with Bearer token." in response.json()["detail"]

def test_chat_empty_bearer_token_rejected(client: TestClient, prod_env):
    """Verifies that an empty or whitespace Bearer header is rejected with HTTP 401."""
    response = client.post(
        "/api/v1/copilot/chat",
        headers={"Authorization": "Bearer   "},
        json={"message": "Explain file entropy"}
    )
    assert response.status_code == 401

def test_chat_expired_jwt_token_rejected(client: TestClient, prod_env):
    """Verifies that an expired JWT token returns HTTP 401."""
    expired_token = generate_test_jwt(exp_offset=-3600)  # Expired 1 hour ago
    response = client.post(
        "/api/v1/copilot/chat",
        headers={"Authorization": f"Bearer {expired_token}"},
        json={"message": "Explain section entropy."}
    )
    assert response.status_code == 401
    detail = response.json().get("detail", "")
    assert "expired" in detail.lower() or "invalid" in detail.lower()

def test_chat_demo_token_rejected_in_production(client: TestClient, prod_env):
    """Verifies that demo tokens are rejected when running in production environment."""
    response = client.post(
        "/api/v1/copilot/chat",
        headers={"Authorization": "Bearer demo-token"},
        json={"message": "Analyze sample"}
    )
    assert response.status_code == 401
    assert "Demo authentication tokens are disabled in production" in response.json()["detail"]

@patch("google.genai.models.AsyncModels.generate_content", new_callable=AsyncMock)
def test_chat_valid_bearer_token_accepted(mock_generate, client: TestClient, prod_env):
    """Verifies that a valid signed JWT Bearer token authenticates successfully and generates a response."""
    mock_resp = MagicMock()
    mock_resp.text = "The entropy score of 6.4 suggests standard uncompressed executable sections."
    mock_generate.return_value = mock_resp

    valid_token = generate_test_jwt()
    response = client.post(
        "/api/v1/copilot/chat",
        headers={"Authorization": f"Bearer {valid_token}"},
        json={"message": "Explain entropy 6.4", "history": []}
    )
    assert response.status_code == 200
    data = response.json()
    assert "reply" in data
    assert "entropy" in data["reply"]

@patch("google.genai.models.AsyncModels.generate_content", new_callable=AsyncMock)
def test_chat_lowercase_authorization_header_accepted(mock_generate, client: TestClient, prod_env):
    """Verifies that lowercase 'authorization: bearer <token>' headers from reverse proxies are handled correctly."""
    mock_resp = MagicMock()
    mock_resp.text = "Multilingual support active: PE headers analyzed."
    mock_generate.return_value = mock_resp

    valid_token = generate_test_jwt()
    response = client.post(
        "/api/v1/copilot/chat",
        headers={"authorization": f"bearer {valid_token}"},
        json={"message": "Test proxy casing", "history": []}
    )
    assert response.status_code == 200

@patch("google.genai.models.AsyncModels.generate_content_stream")
def test_chat_stream_valid_bearer_token_accepted(mock_stream, client: TestClient, prod_env):
    """Verifies that valid Bearer token works with streaming SSE endpoint."""
    async def fake_stream(*args, **kwargs):
        for chunk in ["Scanning ", "PE ", "headers..."]:
            c = MagicMock()
            c.text = chunk
            yield c

    mock_stream.side_effect = fake_stream

    valid_token = generate_test_jwt()
    response = client.post(
        "/api/v1/copilot/chat/stream",
        headers={"Authorization": f"Bearer {valid_token}"},
        json={"message": "Analyze file", "history": []}
    )
    assert response.status_code == 200
    assert "text/event-stream" in response.headers["content-type"]
    assert "data: " in response.text
