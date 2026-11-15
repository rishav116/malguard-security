from typing import Optional, Dict, Any, List
from fastapi import APIRouter, Depends, Request, HTTPException, status
from fastapi.responses import StreamingResponse

from app.core.auth import get_current_user, UserIdentity
from app.models.schemas import (
    CopilotChatRequest,
    CopilotChatResponse,
    SuggestedQuestionsResponse,
)
from app.services.gemini_assistant import gemini_copilot_service

router = APIRouter(tags=["Gemini Copilot"])

def extract_bearer_token(request: Request) -> Optional[str]:
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header.replace("Bearer ", "").strip()
    return None

@router.post("/chat", response_model=CopilotChatResponse)
async def chat_with_copilot(
    request_data: CopilotChatRequest,
    request: Request,
    current_user: UserIdentity = Depends(get_current_user),
):
    """
    Submits a conversational query to the Gemini AI Security Assistant (non-streaming).
    Supports English, Hindi, and Hinglish.
    Optionally grounds the response on the authenticated user's saved malware scan.
    Enforces tenant isolation: users can only query their own scans.
    """
    raw_token = extract_bearer_token(request)
    return await gemini_copilot_service.chat(
        request=request_data,
        user_id=current_user.user_id,
        raw_token=raw_token
    )

@router.post("/chat/stream")
async def stream_chat_with_copilot(
    request_data: CopilotChatRequest,
    request: Request,
    current_user: UserIdentity = Depends(get_current_user),
):
    """
    Streams a conversational query to the Gemini AI Security Assistant in real time via SSE.
    Yields progressive tokens, initial metadata, and completion events.
    """
    raw_token = extract_bearer_token(request)
    return StreamingResponse(
        gemini_copilot_service.stream_chat(
            request=request_data,
            user_id=current_user.user_id,
            raw_token=raw_token
        ),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        }
    )

@router.get("/suggested-questions", response_model=SuggestedQuestionsResponse)
def get_suggested_questions():
    """
    Returns curated security prompts and questions in English, Hinglish, and Hindi.
    """
    return SuggestedQuestionsResponse(
        categories={
            "english": [
                {
                    "id": "en-1",
                    "title": "Explain Entropy in PE Files",
                    "prompt": "What does section entropy tell a malware analyst about a Windows PE binary?"
                },
                {
                    "id": "en-2",
                    "title": "Why Inconclusive Verdict?",
                    "prompt": "Why is my scan verdict marked INCONCLUSIVE, and what is the difference between production ClamAV and the test emulator?"
                },
                {
                    "id": "en-3",
                    "title": "Dangerous Windows APIs",
                    "prompt": "Which Windows API imports indicate process injection or code hollowing techniques?"
                },
                {
                    "id": "en-4",
                    "title": "Random Forest ML Explainer",
                    "prompt": "How does MALGUARD AI's 69-feature Random Forest model detect structural anomalies in executables?"
                }
            ],
            "hinglish": [
                {
                    "id": "hi-en-1",
                    "title": "File Safe Hai Ya Suspicious?",
                    "prompt": "Yeh file safe lag rahi hai ya suspicious? Iske headers aur entropy check karke samjhao."
                },
                {
                    "id": "hi-en-2",
                    "title": "High Entropy Ka Matlab",
                    "prompt": "Agar kisi PE file ki entropy 7 se zyada ho toh iska kya matlab hota hai? Kya yeh packed hai?"
                },
                {
                    "id": "hi-en-3",
                    "title": "ClamAV Emulator Ki Limit",
                    "prompt": "Development test emulator aur real ClamAV engine me kya difference hai? Clean file ko inconclusive kyu bolte hain?"
                }
            ],
            "hindi": [
                {
                    "id": "hi-1",
                    "title": "मैलवेयर का पता कैसे लगाएं?",
                    "prompt": "विंडोज पीई फ़ाइलों में दुर्भावनापूर्ण कोड (Malware) की पहचान कैसे की जाती है?"
                },
                {
                    "id": "hi-2",
                    "title": "एंट्रॉपी और पैकिंग",
                    "prompt": "फ़ाइल एंट्रॉपी क्या होती है और यह मैलवेयर का पता लगाने में कैसे मदद करती है?"
                }
            ]
        }
    )

