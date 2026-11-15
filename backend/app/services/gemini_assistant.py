import time
import json
import asyncio
from typing import Dict, Any, List, Optional, AsyncGenerator
from datetime import datetime, timezone
from collections import defaultdict
from fastapi import HTTPException, status
from google import genai
from google.genai import types

from app.config import settings
from app.core.logging import logger
from app.models.schemas import (
    CopilotChatRequest,
    CopilotChatResponse,
    ChatMessage,
)
from app.services.scan_repository import scan_repository

COPILOT_SYSTEM_PROMPT = """You are MALGUARD AI Security Copilot, an elite cybersecurity assistant specializing in Windows PE malware analysis, reverse engineering, static binary inspection, and defensive threat intelligence.

Core Capabilities:
1. Windows PE Headers & Sections: PE32/PE32+ structure (.text, .data, .rsrc), Shannon entropy (benign typical < 6.8, packed/encrypted > 7.2), Import Address Tables (IAT), and suspicious injection APIs (VirtualAllocEx, WriteProcessMemory, CreateRemoteThread, SetWindowsHookEx).
2. Machine Learning Telemetry: Explain 69 static PE features and conservative Random Forest predictions strictly as model probability estimates, never as infallible proof or guarantees.
3. Signatures & Hashes: ClamAV detections, EICAR antivirus test standards, and cryptographic digests (SHA-256, SHA-1, MD5).

CRITICAL SECURITY LANGUAGE & CONSERVATIVE VERDICT RULES:
- Never Translate ML Scores to "File Safety": Never declare a file "X% safe" or state that a low ML threat score guarantees the binary is harmless. Always refer to it strictly as "model-estimated benign probability" or "model-estimated threat probability".
- Low Entropy != Safe: Never claim a file is safe solely because entropy is normal (< 6.8) or because Random Forest predicts benign. Real-world malware can be uncompressed, unpacked, and unencrypted.
- ClamAV Development-Only Emulator Disclosure: Clearly explain that the current ClamAV service is a development-only EICAR test emulator, NOT official production Cisco ClamAV antivirus protection.
- Preserve INCONCLUSIVE Verdict: Whenever official antivirus signature verification is unavailable or when relying on the test emulator, explicitly state that the verdict remains INCONCLUSIVE because definitive clean verdicts require active production signature scanning.
- Grounding: Ground answers strictly on provided scan metadata. Never fabricate CVEs, malware family names, or indicators not in the data.
- Defense-Only: Never generate functional exploit payloads, reverse shells, or bypasses. Always advise on sandboxing, containment, and defense.

MULTILINGUAL FLUENCY:
- Support English, Hindi (हिंदी), and Hinglish (natural Romanized Hindi written in Latin script, e.g., "Is file ka model-estimated benign probability 85% hai, par isko safe declare nahi kiya ja sakta kyunki production ClamAV signature verification abhi unavailable hai aur verdict INCONCLUSIVE hai").
- Automatically match the user's language. Keep technical terms (entropy, imports, sections, PE header, Random Forest) in Latin script.
- Format responses cleanly with markdown headings (##), bold terms (**term**), bullet points (*), and syntax-highlighted code blocks (```).
"""

class GeminiCopilotService:
    """
    Manages Gemini AI Copilot sessions, grounding on authenticated Supabase scan metadata,
    enforcing tenant scan ownership, input sanitization, rate limiting, and real-time streaming.
    """

    def __init__(self):
        self.api_key = settings.GEMINI_API_KEY
        self.model = settings.GEMINI_MODEL or "gemini-3.5-flash"
        self._client: Optional[genai.Client] = None
        # In-memory sliding window rate limiter: user_id -> List[timestamp]
        self._user_rate_limits: Dict[str, List[float]] = defaultdict(list)
        self.rate_limit_window_sec = 60.0
        self.rate_limit_max_requests = 30  # Generous threshold for interactive analyst chats
        self._cached_client: Optional[genai.Client] = None

    def _get_client(self) -> genai.Client:
        """Returns or creates a reusable singleton Gemini client instance."""
        if self._cached_client is None:
            if not self.api_key:
                logger.error("GEMINI_API_KEY is not configured.")
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Gemini AI Assistant is not configured on this server (GEMINI_API_KEY missing)."
                )
            self._cached_client = genai.Client(api_key=self.api_key)
        return self._cached_client

    def _check_rate_limit(self, user_id: str):
        now = time.time()
        window_start = now - self.rate_limit_window_sec
        recent = [t for t in self._user_rate_limits[user_id] if t > window_start]
        if len(recent) >= self.rate_limit_max_requests:
            logger.warning(f"Rate limit exceeded for user {user_id}")
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded. Maximum {self.rate_limit_max_requests} messages per minute."
            )
        recent.append(now)
        self._user_rate_limits[user_id] = recent

    def _format_scan_grounding(self, scan: Dict[str, Any]) -> str:
        pe = scan.get("pe_summary", {})
        clamav_msg = str(scan.get("clamav_message", ""))
        is_emulator = (
            "dev-only" in clamav_msg.lower()
            or "emulator" in clamav_msg.lower()
            or scan.get("clamav_status") == "clean" and "test signatures" in clamav_msg.lower()
        )

        ml_pred = scan.get("ml_prediction", "N/A")
        ml_score = scan.get("ml_confidence_score")
        ml_prob_str = f"{round(float(ml_score) * 100, 1)}%" if ml_score is not None else "N/A"

        return (
            "\n[GROUNDING CONTEXT: AUTHENTICATED USER SCAN ARTIFACT]\n"
            f"- File Name: {scan.get('file_name', 'unknown.bin')}\n"
            f"- File Size: {scan.get('formatted_size', '0 B')} ({scan.get('file_size_bytes', 0)} bytes)\n"
            f"- SHA-256 Digest: {scan.get('sha256', 'N/A')}\n"
            f"- Conservative Verdict: {scan.get('verdict', 'INCONCLUSIVE')}\n"
            f"- Verdict Reasons: {json.dumps(scan.get('verdict_reasons', []))}\n"
            f"- Target Architecture: {pe.get('machine', 'N/A')}\n"
            f"- Subsystem: {pe.get('subsystem', 'N/A')}\n"
            f"- PE Sections Count: {pe.get('number_of_sections', 0)}\n"
            f"- Shannon Entropy: {pe.get('file_entropy', 0.0)}\n"
            f"- Imported DLLs: {pe.get('imported_dlls_count', 0)}\n"
            f"- Total API Imports: {pe.get('total_imports_count', 0)}\n"
            f"- Suspicious Indicators Count: {pe.get('suspicious_indicators_count', 0)}\n"
            f"- ClamAV Status: {scan.get('clamav_status', 'unavailable')}\n"
            f"- ClamAV Matched Signature: {scan.get('clamav_signature') or 'None'}\n"
            f"- ClamAV Engine Type: {'Development-Only EICAR Emulator (Test daemon only; NOT official production ClamAV antivirus)' if is_emulator else 'Official Production ClamAV Antivirus'}\n"
            f"- Random Forest ML Inference: {ml_pred} (Model-Estimated Benign Probability: {ml_prob_str}; statistical estimate only, NOT proof of safety)\n"
            f"- Scanned At: {scan.get('created_at', 'N/A')}\n"
            "[END OF GROUNDING CONTEXT]\n"
        )

    def _prepare_contents(
        self,
        request: CopilotChatRequest,
        scan_context_str: str = ""
    ) -> List[types.Content]:
        """Constructs compact conversation contents limiting history to the last 4 turns."""
        contents: List[types.Content] = []

        # Retain last 4 turns for context window speed and cost efficiency
        for h in request.history[-4:]:
            role = "user" if h.role in ["user", "human"] else "model"
            contents.append(types.Content(
                role=role,
                parts=[types.Part.from_text(text=h.content)]
            ))

        # Append current user prompt with grounding
        prompt_content = ""
        if scan_context_str:
            prompt_content += scan_context_str + "\n"
        prompt_content += f"User Query: {request.message}"

        contents.append(types.Content(
            role="user",
            parts=[types.Part.from_text(text=prompt_content)]
        ))
        return contents

    def _get_model_fallback_list(self) -> List[str]:
        candidates = [
            self.model,
            "gemini-2.5-flash",
            "gemini-2.0-flash",
            "gemini-1.5-flash",
            "gemini-3.5-flash-lite",
        ]
        deduped = []
        seen = set()
        for c in candidates:
            if c and c not in seen:
                seen.add(c)
                deduped.append(c)
        return deduped

    async def chat(
        self,
        request: CopilotChatRequest,
        user_id: str,
        raw_token: Optional[str] = None
    ) -> CopilotChatResponse:
        """
        Non-streaming chat request against Google Gemini with grounding on user's scan metadata.
        Uses non-blocking asynchronous execution.
        """
        self._check_rate_limit(user_id)

        if len(request.message) > settings.GEMINI_MAX_INPUT_CHARS:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Message exceeds maximum allowed length of {settings.GEMINI_MAX_INPUT_CHARS} characters."
            )

        scan_context_str = ""
        scan_record_summary: Optional[Dict[str, Any]] = None

        if request.scan_id:
            scan = await scan_repository.get_scan_by_id(
                user_id=user_id,
                scan_id=request.scan_id,
                raw_token=raw_token
            )
            if not scan:
                logger.warning(f"User {user_id} attempted access to non-existent or foreign scan {request.scan_id}")
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Specified scan record was not found or does not belong to your account."
                )
            scan_context_str = self._format_scan_grounding(scan)
            scan_record_summary = {
                "scan_id": scan.get("id"),
                "file_name": scan.get("file_name"),
                "sha256": scan.get("sha256"),
                "verdict": scan.get("verdict"),
            }

        client = self._get_client()
        contents = self._prepare_contents(request, scan_context_str)
        models_to_try = self._get_model_fallback_list()

        last_error = None
        successful_reply = None
        model_used = models_to_try[0]

        for m_name in models_to_try:
            try:
                config = types.GenerateContentConfig(
                    system_instruction=COPILOT_SYSTEM_PROMPT,
                    temperature=0.3,
                    max_output_tokens=1000,
                )
                response = await client.aio.models.generate_content(
                    model=m_name,
                    contents=contents,
                    config=config
                )
                if response and response.text:
                    successful_reply = response.text.strip()
                    model_used = m_name
                    break
            except Exception as e:
                logger.warning(f"Gemini non-streaming generation failed on model '{m_name}': {e}")
                last_error = e
                continue

        if not successful_reply:
            logger.error(f"All Gemini models exhausted. Final error: {last_error}")
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Gemini AI Assistant error: {str(last_error)}"
            )

        return CopilotChatResponse(
            reply=successful_reply,
            scan_context_used=scan_record_summary,
            model_used=model_used,
            grounded_on_scan=bool(request.scan_id),
            timestamp=datetime.now(timezone.utc)
        )

    async def stream_chat(
        self,
        request: CopilotChatRequest,
        user_id: str,
        raw_token: Optional[str] = None
    ) -> AsyncGenerator[str, None]:
        """
        Streams generated responses token-by-token via Server-Sent Events (SSE).
        Yields JSON-formatted event strings conforming to SSE protocol.
        """
        # 1. Rate Limit & Input Validation
        self._check_rate_limit(user_id)

        if len(request.message) > settings.GEMINI_MAX_INPUT_CHARS:
            error_data = json.dumps({"event": "error", "detail": f"Message exceeds limit of {settings.GEMINI_MAX_INPUT_CHARS} characters."})
            yield f"data: {error_data}\n\n"
            return

        # 2. Grounding Context
        scan_context_str = ""
        scan_record_summary: Optional[Dict[str, Any]] = None

        if request.scan_id:
            scan = await scan_repository.get_scan_by_id(
                user_id=user_id,
                scan_id=request.scan_id,
                raw_token=raw_token
            )
            if not scan:
                logger.warning(f"User {user_id} unauthorized or missing scan {request.scan_id}")
                error_data = json.dumps({"event": "error", "detail": "Specified scan record was not found or access denied."})
                yield f"data: {error_data}\n\n"
                return

            scan_context_str = self._format_scan_grounding(scan)
            scan_record_summary = {
                "scan_id": scan.get("id"),
                "file_name": scan.get("file_name"),
                "sha256": scan.get("sha256"),
                "verdict": scan.get("verdict"),
            }

        client = self._get_client()
        contents = self._prepare_contents(request, scan_context_str)
        models_to_try = self._get_model_fallback_list()

        # Send initial metadata event immediately
        meta_event = json.dumps({
            "event": "metadata",
            "model": models_to_try[0],
            "grounded_on_scan": bool(request.scan_id),
            "scan_context": scan_record_summary,
        })
        yield f"data: {meta_event}\n\n"

        # 3. Stream from Gemini with Fallback
        streaming_succeeded = False
        last_error = None

        for m_name in models_to_try:
            try:
                config = types.GenerateContentConfig(
                    system_instruction=COPILOT_SYSTEM_PROMPT,
                    temperature=0.3,
                    max_output_tokens=1000,
                )
                stream = await client.aio.models.generate_content_stream(
                    model=m_name,
                    contents=contents,
                    config=config
                )
                async for chunk in stream:
                    if chunk.text:
                        token_event = json.dumps({
                            "event": "token",
                            "text": chunk.text
                        })
                        yield f"data: {token_event}\n\n"

                streaming_succeeded = True
                done_event = json.dumps({
                    "event": "done",
                    "model_used": m_name,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                })
                yield f"data: {done_event}\n\n"
                break

            except Exception as e:
                logger.warning(f"Streaming failed on model '{m_name}': {e}")
                last_error = e
                continue

        if not streaming_succeeded:
            logger.error(f"All Gemini models exhausted during streaming. Error: {last_error}")
            err_event = json.dumps({
                "event": "error",
                "detail": f"Assistant temporarily unavailable: {str(last_error)}"
            })
            yield f"data: {err_event}\n\n"

# Global singleton
gemini_copilot_service = GeminiCopilotService()
