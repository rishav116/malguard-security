import uuid
import httpx
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, UploadFile, File, HTTPException, status, Request
from app.config import settings
from app.core.auth import get_current_user, UserIdentity
from app.core.security import validate_pe_magic_bytes, compute_hashes, PEValidationError
from app.core.logging import logger
from app.models.schemas import (
    ScanResponse,
    VerdictEnum,
    StorageScanRequest,
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

async def _execute_scan_pipeline(
    binary_data: bytes,
    filename: str,
    current_user: UserIdentity,
    request: Request
) -> ScanResponse:
    lower_name = filename.lower()
    is_eicar = binary_data.strip().startswith(b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
    
    # 1. Extension validation (Allows standard Windows PE binaries, or .com for authenticated EICAR test string)
    if not (lower_name.endswith(".exe") or lower_name.endswith(".dll") or (is_eicar and lower_name.endswith(".com"))):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported file format: '{filename}'. Only Windows PE binaries (.exe, .dll) are accepted."
        )

    total_bytes = len(binary_data)
    if total_bytes > settings.MAX_FILE_SIZE_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File exceeds maximum allowed size of 10 MB ({format_bytes(total_bytes)} received)."
        )

    # 2. PE Magic Bytes Verification (MZ header + PE offset check; bypassed only for standard EICAR test string)
    if not is_eicar:
        try:
            validate_pe_magic_bytes(binary_data)
        except PEValidationError as e:
            logger.warning(f"File '{filename}' failed PE validation: {e}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid Windows PE structure: {str(e)}"
            )

    # 3. Cryptographic Hashing
    hashes = compute_hashes(binary_data)
    scan_id = str(uuid.uuid4())
    logger.info(f"Initiated scan {scan_id} for '{filename}' ({hashes['sha256']}) by owner {current_user.user_id}")

    # 4. Static PE Analysis via pefile
    if not is_eicar:
        try:
            pe_analysis = analyze_pe_binary(binary_data)
        except ValueError as e:
            logger.error(f"PE static analysis failed: {e}")
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Unable to parse PE headers: {str(e)}"
            )
    else:
        from app.models.schemas import PEAnalysisResult, PEHeaderInfo
        pe_analysis = PEAnalysisResult(
            status="eicar_test_pattern",
            headers=PEHeaderInfo(
                machine="DOS",
                machine_hex="0x0",
                number_of_sections=0,
                time_date_stamp=0,
                compilation_timestamp="N/A",
                characteristics_hex="0x0",
                is_dll=False,
                is_executable_image=True,
                subsystem="DOS_COM",
                magic="DOS COM Executable",
                entry_point_rva="0x0",
                image_base="0x0"
            ),
            sections=[],
            imported_dlls_count=0,
            imported_dlls=[],
            total_imports_count=0,
            exported_functions_count=0,
            exported_functions=[],
            file_entropy=3.14,
            suspicious_indicators=["EICAR standard antivirus test signature pattern"]
        )

    # 5. Isolated ClamAV Signature Scan
    clamav_result = clamav_service.scan_stream(binary_data)

    # 6. Machine Learning Inference (Random Forest)
    ml_result = ml_service.predict(pe_data=pe_analysis, file_size=total_bytes, raw_bytes=binary_data)

    # 7. Synthesize Conservative Verdict
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
            if clamav_service.is_starting():
                verdict_reasons.append("ClamAV signature engine is currently initializing (loading official database signatures into memory).")
            elif clamav_service.is_failed():
                verdict_reasons.append("ClamAV signature daemon encountered a runtime startup failure.")
            else:
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

    # 8. Persistent Storage in Supabase PostgreSQL (Never stores binary contents)
    raw_token = extract_bearer_token(request)
    await scan_repository.save_scan(scan_response, user_id=current_user.user_id, raw_token=raw_token)

    return scan_response

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
    Optimal for binaries <= 4.5 MB.
    """
    filename = file.filename or "unknown_binary"
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

    return await _execute_scan_pipeline(bytes(content), filename, current_user, request)

@router.post("/scans/storage", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
@router.post("/scan/storage", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def create_scan_from_storage(
    request: Request,
    payload: StorageScanRequest,
    current_user: UserIdentity = Depends(get_current_user)
):
    """
    Scans a Windows PE binary uploaded directly to private Supabase Storage (bypasses Vercel's 4.5 MB payload limit for files up to 10 MB).
    Immediately deletes the binary payload after retrieval. Zero public binary exposure.
    """
    storage_path = payload.storage_path.strip().lstrip("/")
    if ".." in storage_path or not storage_path:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid storage path.")

    filename = payload.file_name or storage_path.split("/")[-1] or "uploaded_binary.exe"
    bucket_name = "malguard-quarantine"
    raw_token = extract_bearer_token(request)

    headers = {}
    if raw_token:
        headers["Authorization"] = f"Bearer {raw_token}"
    if settings.SUPABASE_ANON_KEY:
        headers["apikey"] = settings.SUPABASE_ANON_KEY

    download_url = f"{settings.SUPABASE_URL.rstrip('/')}/storage/v1/object/authenticated/{bucket_name}/{storage_path}"
    binary_data = b""

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(download_url, headers=headers)
            if resp.status_code != 200:
                logger.error(f"Failed to fetch {storage_path} from Supabase storage: {resp.status_code}")
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"File not found in private quarantine storage or unauthorized (HTTP {resp.status_code})."
                )
            binary_data = resp.content
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Storage retrieval error: {e}")
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Failed to retrieve file from quarantine storage: {str(e)}"
        )
    finally:
        # Guarantee binary payload is deleted from quarantine storage immediately
        try:
            delete_url = f"{settings.SUPABASE_URL.rstrip('/')}/storage/v1/object/{bucket_name}"
            async with httpx.AsyncClient(timeout=10.0) as client:
                await client.request("DELETE", delete_url, headers=headers, json={"prefixes": [storage_path]})
                logger.info(f"Purged quarantine binary '{storage_path}' from storage.")
        except Exception as del_err:
            logger.warning(f"Could not purge quarantine file '{storage_path}': {del_err}")

    # Integrity verification if client supplied SHA-256
    if payload.sha256:
        calculated_sha256 = compute_hashes(binary_data)["sha256"]
        if calculated_sha256.lower() != payload.sha256.lower():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Integrity check failed: Client SHA-256 does not match downloaded binary payload."
            )

    return await _execute_scan_pipeline(binary_data, filename, current_user, request)


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
        "verdict": VerdictEnum.MALICIOUS.value if result.matched else VerdictEnum.INCONCLUSIVE.value,
        "verdict_reasons": [f"Confirmed malware signature match: {result.signature_name}"] if result.matched else ["No threat signature matched"],
        "clamav_result": result.model_dump()
    }
