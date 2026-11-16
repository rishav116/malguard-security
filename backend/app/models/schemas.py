from enum import Enum
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
from pydantic import BaseModel, Field

class VerdictEnum(str, Enum):
    MALICIOUS = "MALICIOUS"
    SUSPICIOUS = "SUSPICIOUS"
    NO_THREAT_DETECTED = "NO_THREAT_DETECTED"
    INCONCLUSIVE = "INCONCLUSIVE"

class HealthResponse(BaseModel):
    status: str = "online"
    service: str = "MALGUARD AI Detection Engine"
    version: str
    environment: str
    engines: Dict[str, str]
    diagnostics: Optional[Dict[str, Any]] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class PESectionDetail(BaseModel):
    name: str
    virtual_size: int
    raw_size: int
    entropy: float
    characteristics_hex: str
    is_executable: bool
    is_writable: bool

class PEHeaderInfo(BaseModel):
    machine: str
    machine_hex: str
    number_of_sections: int
    time_date_stamp: int
    compilation_timestamp: Optional[str] = None
    characteristics_hex: str
    is_dll: bool
    is_executable_image: bool
    subsystem: str
    magic: str
    entry_point_rva: str
    image_base: str

class PEAnalysisResult(BaseModel):
    status: str = "success"
    error: Optional[str] = None
    headers: PEHeaderInfo
    sections: List[PESectionDetail]
    imported_dlls_count: int
    imported_dlls: List[str]
    total_imports_count: int
    exported_functions_count: int
    exported_functions: List[str]
    file_entropy: float
    suspicious_indicators: List[str]

class ClamAVResult(BaseModel):
    status: str  # "clean" | "infected" | "unavailable" | "error"
    available: bool
    matched: bool
    is_emulator: bool = False
    signature_name: Optional[str] = None
    scan_time_ms: Optional[float] = None
    message: str

class MLInferenceResult(BaseModel):
    status: str  # "loaded" | "model_not_loaded" | "unavailable" | "error"
    available: bool
    model_name: str = "Random Forest PE Classifier"
    prediction: Optional[str] = None  # "malicious" | "benign" | None
    confidence_score: Optional[float] = None  # 0.0 to 1.0 (never fabricated!)
    features_used_count: int = 0
    message: str

class ScanResponse(BaseModel):
    scan_id: str
    file_name: str
    file_size_bytes: int
    formatted_size: str
    hashes: Dict[str, str]  # sha256, sha1, md5
    owner_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Engine analysis results
    pe_analysis: PEAnalysisResult
    clamav: ClamAVResult
    ml_inference: MLInferenceResult
    
    # Final synthesized verdict (strictly conservative)
    verdict: VerdictEnum
    verdict_reasons: List[str]
    pipeline_status: str

# Copilot AI Schemas (Phase 5)
class ChatMessage(BaseModel):
    role: str = Field(description="Role of the message sender: 'user' or 'model'")
    content: str = Field(description="Text content of the chat message")

class CopilotChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=2000, description="User's query")
    scan_id: Optional[str] = Field(default=None, description="Optional scan UUID to ground the analysis")
    history: List[ChatMessage] = Field(default_factory=list, description="Prior conversational context")

class CopilotChatResponse(BaseModel):
    reply: str
    scan_context_used: Optional[Dict[str, Any]] = None
    model_used: str
    grounded_on_scan: bool = False
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class SuggestedQuestionsResponse(BaseModel):
    categories: Dict[str, List[Dict[str, str]]]

class StorageScanRequest(BaseModel):
    storage_path: str = Field(..., description="Relative path in private Supabase Storage bucket (malguard-quarantine)")
    file_name: Optional[str] = Field(default=None, description="Original filename")
    sha256: Optional[str] = Field(default=None, description="Client computed SHA-256 for integrity verification")

