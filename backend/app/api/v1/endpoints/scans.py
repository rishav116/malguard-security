import uuid
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, UploadFile, File, HTTPException, status, Request
from app.config import settings
from app.core.auth import get_current_user, UserIdentity
from app.core.security import validate_pe_magic_bytes, compute_hashes, PEValidationError
from app.core.logging import logger
from app.models.schemas import (
    ScanResponse,
    VerdictEnum,
)
from app.services.pe_analyzer import analyze_pe_binary
from app.services.clamav_scanner import clamav_service
from app.services.ml_classifier import ml_service
from app.services.scan_repository import scan_repository

router = APIRouter(tags=["Scans"])

def format_bytes(num_bytes: int) -> str:
    for unit in ["Bytes", "KB", "MB", "GB"]:
        if num_bytes < 1024.0:
            return f"{num_bytes:.2f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.2f} TB"

def extract_bearer_token(request: Request) -> Optional[str]:
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header.replace("Bearer ", "").strip()
    return None

@router.post("/scans", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
@router.post("/scan", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def create_scan(
    request: Request,
    file: UploadFile = File(..., description="Windows PE binary (.exe or .dll, max 10 MB)"),
    current_user: UserIdentity = Depends(get_current_user)
):
    """
    Submits a Windows PE binary for isolated static analysis, cryptographic fingerprinting,
    ClamAV signature scanning, and ML classification.
    Requires an authenticated user session (Supabase JWT or authorized demo token).
    Persists scan results to Supabase PostgreSQL without saving binary payload.
    """
    filename = file.filename or "unknown_binary"
    lower_name = filename.lower()
    
    # 1. Extension validation
    if not (lower_name.endswith(".exe") or lower_name.endswith(".dll")):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported file format: '{filename}'. Only Windows PE binaries (.exe, .dll) are accepted."
        )

    # 2. Size-controlled read (Max 10 MB)
    max_bytes = settings.MAX_FILE_SIZE_BYTES
    content = bytearray()
    chunk_size = 64 * 1024  # 64 KB chunks
    
    while True:
        chunk = await file.read(chunk_size)
        if not chunk:
            break
        content.extend(chunk)
        if len(content) > max_bytes:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"File exceeds maximum allowed size of 10 MB ({format_bytes(len(content))} received)."
            )

    total_bytes = len(content)
    binary_data = bytes(content)

    # 3. PE Magic Bytes Verification (MZ header + PE offset check)
    try:
        validate_pe_magic_bytes(binary_data)
    except PEValidationError as e:
        logger.warning(f"File '{filename}' failed PE validation: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid Windows PE structure: {str(e)}"
        )

    # 4. Cryptographic Hashing
    hashes = compute_hashes(binary_data)
    scan_id = str(uuid.uuid4())
    logger.info(f"Initiated scan {scan_id} for '{filename}' ({hashes['sha256']}) by owner {current_user.user_id}")

    # 5. Static PE Analysis via pefile
    try:
        pe_analysis = analyze_pe_binary(binary_data)
    except ValueError as e:
        logger.error(f"PE static analysis failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Unable to parse PE headers: {str(e)}"
        )

    # 6. Isolated ClamAV Signature Scan
    clamav_result = clamav_service.scan_stream(binary_data)

    # 7. Machine Learning Inference (Random Forest)
    ml_result = ml_service.predict(pe_data=pe_analysis, file_size=total_bytes, raw_bytes=binary_data)

    # 8. Synthesize Conservative Verdict
    verdict_reasons: List[str] = []
    
    if clamav_result.matched:
        verdict = VerdictEnum.MALICIOUS
        verdict_reasons.append(f"Confirmed malware signature match: {clamav_result.signature_name}")
    elif ml_result.available and ml_result.prediction == "malicious" and (ml_result.confidence_score or 0) >= 0.75:
        verdict = VerdictEnum.SUSPICIOUS
        verdict_reasons.append(f"Random Forest classifier flagged suspicious structural anomalies (Estimated probability: {ml_result.confidence_score * 100:.1f}%)")
    elif len(pe_analysis.suspicious_indicators) >= 2 and pe_analysis.file_entropy > 7.3:
        verdict = VerdictEnum.SUSPICIOUS
        verdict_reasons.append(f"Multiple high-risk indicators detected: High entropy ({pe_analysis.file_entropy:.2f}) and sensitive API injection imports.")
    elif clamav_result.available and clamav_result.status == "clean" and ml_result.available and ml_result.prediction == "benign":
        if clamav_result.is_emulator:
            verdict = VerdictEnum.INCONCLUSIVE
            verdict_reasons.append("ML model classified file as benign, but ClamAV signature scan used the development-only EICAR emulator rather than the official production ClamAV database.")
            verdict_reasons.append("A definitive 'NO_THREAT_DETECTED' verdict strictly requires validation by the official production ClamAV signature database.")
        else:
            verdict = VerdictEnum.NO_THREAT_DETECTED
            verdict_reasons.append("All scans completed: No signature matches in official ClamAV and benign classification by ML model.")
    else:
        # Default strictly to INCONCLUSIVE when engines are offline/unavailable
        verdict = VerdictEnum.INCONCLUSIVE
        if not clamav_result.available:
            verdict_reasons.append("ClamAV signature engine was unavailable during this scan.")
        if not ml_result.available:
            verdict_reasons.append("Random Forest ML model is not loaded.")
        verdict_reasons.append("Static PE metadata and cryptographic hashes were successfully extracted, but a definitive threat verdict requires active backend scanning engines.")

    scan_response = ScanResponse(
        scan_id=scan_id,
        file_name=filename,
        file_size_bytes=total_bytes,
        formatted_size=format_bytes(total_bytes),
        hashes=hashes,
        owner_id=current_user.user_id,
        pe_analysis=pe_analysis,
        clamav=clamav_result,
        ml_inference=ml_result,
        verdict=verdict,
        verdict_reasons=verdict_reasons,
        pipeline_status="completed"
    )

    # 9. Persistent Storage in Supabase PostgreSQL (Never stores binary contents)
    raw_token = extract_bearer_token(request)
    await scan_repository.save_scan(scan_response, user_id=current_user.user_id, raw_token=raw_token)

    return scan_response

@router.get("/scans", response_model=List[Dict[str, Any]])
@router.get("/scans/history", response_model=List[Dict[str, Any]])
async def list_scans(
    request: Request,
    limit: int = 50,
    search: Optional[str] = None,
    verdict: Optional[str] = None,
    current_user: UserIdentity = Depends(get_current_user),
):
    """
    Returns scan history for the authenticated user with search and verdict filtering.
    Enforces user isolation: users cannot view scan records belonging to others.
    """
    raw_token = extract_bearer_token(request)
    return await scan_repository.get_user_scans(
        user_id=current_user.user_id,
        raw_token=raw_token,
        limit=limit,
        search=search,
        verdict=verdict
    )

@router.get("/scans/dashboard/metrics")
async def get_dashboard_metrics(
    request: Request,
    current_user: UserIdentity = Depends(get_current_user),
):
    """
    Computes dashboard metrics, threat breakdown and recent scans for the authenticated user.
    """
    raw_token = extract_bearer_token(request)
    return await scan_repository.get_dashboard_metrics(
        user_id=current_user.user_id,
        raw_token=raw_token
    )

@router.get("/scans/{scan_id}")
async def get_scan_detail(
    scan_id: str,
    request: Request,
    current_user: UserIdentity = Depends(get_current_user),
):
    """
    Retrieves a single scan record by scan_id with strict user ownership validation.
    """
    raw_token = extract_bearer_token(request)
    record = await scan_repository.get_scan_by_id(
        user_id=current_user.user_id,
        scan_id=scan_id,
        raw_token=raw_token
    )
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan record '{scan_id}' not found or you do not have permission to access it."
        )
    return record

@router.post("/scans/test-eicar")
async def test_eicar_signature(
    current_user: UserIdentity = Depends(get_current_user),
):
    """
    Safely tests ClamAV signature detection using the standard EICAR string.
    Does not execute or download any malware binary.
    """
    from app.services.clamd_daemon import EICAR_STANDARD_STRING
    result = clamav_service.scan_stream(EICAR_STANDARD_STRING)
    return {
        "status": "success",
        "tested_signature": "EICAR Standard Antivirus Test String",
        "clamav_result": result.model_dump()
    }
