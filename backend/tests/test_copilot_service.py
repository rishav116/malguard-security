import json
import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from fastapi.testclient import TestClient
from app.main import app
from app.core.auth import get_current_user, UserIdentity
from app.models.schemas import CopilotChatRequest
from app.services.gemini_assistant import gemini_copilot_service

@pytest.fixture
def auth_copilot_client() -> TestClient:
    test_user = UserIdentity(
        user_id="copilot-test-analyst-uuid",
        email="analyst@malguard.internal",
        role="authenticated",
        is_demo=False
    )
    app.dependency_overrides[get_current_user] = lambda: test_user
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()

def test_copilot_requires_authentication(client: TestClient):
    response = client.post("/api/v1/copilot/chat", json={"message": "Is this file safe?"})
    assert response.status_code == 401

def test_copilot_stream_requires_authentication(client: TestClient):
    response = client.post("/api/v1/copilot/chat/stream", json={"message": "Is this file safe?"})
    assert response.status_code == 401

def test_copilot_rejects_oversized_message(auth_copilot_client: TestClient):
    long_msg = "A" * 2500  # Exceeds 2000 chars
    response = auth_copilot_client.post("/api/v1/copilot/chat", json={"message": long_msg})
    assert response.status_code in [400, 422]

def test_copilot_suggested_questions(auth_copilot_client: TestClient):
    response = auth_copilot_client.get("/api/v1/copilot/suggested-questions")
    assert response.status_code == 200
    data = response.json()
    assert "categories" in data
    assert "english" in data["categories"]
    assert "hinglish" in data["categories"]
    assert "hindi" in data["categories"]

@patch("google.genai.models.AsyncModels.generate_content", new_callable=AsyncMock)
def test_copilot_chat_mocked_success(mock_generate, auth_copilot_client: TestClient):
    mock_resp = MagicMock()
    mock_resp.text = "Based on static analysis, the Shannon entropy of 6.2 is typical for benign code."
    mock_generate.return_value = mock_resp

    req = {
        "message": "Why is the entropy 6.2?",
        "history": []
    }
    response = auth_copilot_client.post("/api/v1/copilot/chat", json=req)
    assert response.status_code == 200
    data = response.json()
    assert "reply" in data
    assert "entropy" in data["reply"]
    assert data["grounded_on_scan"] is False

@patch("google.genai.models.AsyncModels.generate_content", new_callable=AsyncMock)
def test_copilot_chat_hinglish_support(mock_generate, auth_copilot_client: TestClient):
    mock_resp = MagicMock()
    mock_resp.text = "Yeh file safe lag rahi hai kyunki entropy normal hai aur koi dangerous API nahi mila."
    mock_generate.return_value = mock_resp

    req = {
        "message": "Yeh file safe hai kya bhai?",
        "history": []
    }
    response = auth_copilot_client.post("/api/v1/copilot/chat", json=req)
    assert response.status_code == 200
    data = response.json()
    assert "safe" in data["reply"]

@patch("app.services.scan_repository.scan_repository.get_scan_by_id", new_callable=AsyncMock)
@patch("google.genai.models.AsyncModels.generate_content", new_callable=AsyncMock)
def test_copilot_chat_grounded_on_scan(mock_generate, mock_get_scan, auth_copilot_client: TestClient):
    mock_get_scan.return_value = {
        "id": "scan-12345",
        "file_name": "sample.exe",
        "file_size_bytes": 1024,
        "formatted_size": "1.0 KB",
        "sha256": "abcdef1234567890",
        "verdict": "INCONCLUSIVE",
        "verdict_reasons": ["ClamAV test emulator active"],
        "pe_summary": {"file_entropy": 5.2, "imported_dlls_count": 2},
        "clamav_status": "clean",
        "clamav_message": "Dev-only test emulator",
        "ml_prediction": "benign",
        "ml_confidence_score": 0.05
    }

    mock_resp = MagicMock()
    mock_resp.text = "The scan for sample.exe is marked INCONCLUSIVE because the ClamAV engine used was the development-only EICAR emulator."
    mock_generate.return_value = mock_resp

    req = {
        "message": "Explain the verdict for this scan.",
        "scan_id": "scan-12345"
    }
    response = auth_copilot_client.post("/api/v1/copilot/chat", json=req)
    assert response.status_code == 200
    data = response.json()
    assert data["grounded_on_scan"] is True
    assert data["scan_context_used"]["scan_id"] == "scan-12345"

@patch("app.services.scan_repository.scan_repository.get_scan_by_id", new_callable=AsyncMock)
def test_copilot_rejects_foreign_or_missing_scan(mock_get_scan, auth_copilot_client: TestClient):
    mock_get_scan.return_value = None

    req = {
        "message": "Explain this scan.",
        "scan_id": "foreign-scan-999"
    }
    response = auth_copilot_client.post("/api/v1/copilot/chat", json=req)
    assert response.status_code == 404
    assert "not belong to your account" in response.json()["detail"]

@patch("google.genai.models.AsyncModels.generate_content_stream")
def test_copilot_stream_mocked_success(mock_stream, auth_copilot_client: TestClient):
    async def fake_stream(*args, **kwargs):
        chunks = ["Entropy ", "is ", "normal ", "for ", "this ", "file."]
        for text in chunks:
            c = MagicMock()
            c.text = text
            yield c

    mock_stream.side_effect = fake_stream

    req = {
        "message": "Explain file entropy.",
        "history": []
    }
    response = auth_copilot_client.post("/api/v1/copilot/chat/stream", json=req)
    assert response.status_code == 200
    assert "text/event-stream" in response.headers["content-type"]

    lines = response.text.split("\n\n")
    events = []
    for line in lines:
        if line.startswith("data: "):
            payload = json.loads(line[6:])
            events.append(payload)

    # Validate event sequence: metadata -> tokens -> done
    event_types = [e.get("event") for e in events]
    assert "metadata" in event_types
    assert "token" in event_types
    assert "done" in event_types

    # Reconstruct text
    reconstructed = "".join([e.get("text", "") for e in events if e.get("event") == "token"])
    assert reconstructed == "Entropy is normal for this file."
