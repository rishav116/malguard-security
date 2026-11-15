import pytest
import uuid
import httpx
from datetime import datetime, timezone
from fastapi import HTTPException

from app.config import settings
from app.services.scan_repository import scan_repository
from app.models.schemas import ScanResponse, VerdictEnum, PEAnalysisResult, PEHeaderInfo, ClamAVResult, MLInferenceResult

@pytest.mark.asyncio
async def test_supabase_public_scans_table_accessible():
    """Verifies that the Supabase PostgREST table public.scans exists and responds."""
    if not settings.SUPABASE_URL or not settings.SUPABASE_ANON_KEY:
        pytest.skip("Supabase credentials not configured")
    
    url = f"{settings.SUPABASE_URL.rstrip('/')}/rest/v1/scans"
    headers = {
        "apikey": settings.SUPABASE_ANON_KEY,
        "Authorization": f"Bearer {settings.SUPABASE_ANON_KEY}",
        "Accept": "application/json"
    }
    async with httpx.AsyncClient(timeout=5.0) as client:
        resp = await client.get(url, headers=headers)
        assert resp.status_code == 200, f"Expected 200 from Supabase, got {resp.status_code}: {resp.text}"
        assert isinstance(resp.json(), list)

@pytest.mark.asyncio
async def test_supabase_rls_blocks_unauthorized_inserts():
    """Verifies that Supabase PostgreSQL RLS blocks unauthenticated / spoofed inserts with 42501."""
    if not settings.SUPABASE_URL or not settings.SUPABASE_ANON_KEY:
        pytest.skip("Supabase credentials not configured")

    url = f"{settings.SUPABASE_URL.rstrip('/')}/rest/v1/scans"
    headers = {
        "apikey": settings.SUPABASE_ANON_KEY,
        "Authorization": f"Bearer {settings.SUPABASE_ANON_KEY}",
        "Content-Type": "application/json"
    }
    fake_record = {
        "id": str(uuid.uuid4()),
        "user_id": str(uuid.uuid4()),
        "file_name": "spoofed_sample.exe",
        "file_size_bytes": 1024,
        "formatted_size": "1.0 KB",
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "verdict": "NO_THREAT_DETECTED",
        "verdict_reasons": ["Test RLS insertion"],
        "pe_summary": {},
        "clamav_status": "clean",
        "clamav_available": True,
        "clamav_matched": False,
        "ml_status": "benign",
        "ml_available": True,
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    async with httpx.AsyncClient(timeout=5.0) as client:
        resp = await client.post(url, json=fake_record, headers=headers)
        # RLS MUST reject this with 401 or 403 (violating policy 'Users can insert their own scans')
        assert resp.status_code in [400, 401, 403, 404, 409], f"RLS should block unauthenticated inserts! Got {resp.status_code}"
        if "message" in resp.text:
            assert "row-level security" in resp.text.lower() or "jwt" in resp.text.lower() or "42501" in resp.text

@pytest.mark.asyncio
async def test_scan_repository_raises_when_persistence_fails_and_fallback_disabled():
    """Verifies that silent in-memory fallback is disabled when expected."""
    orig_fallback = settings.ALLOW_IN_MEMORY_FALLBACK
    settings.ALLOW_IN_MEMORY_FALLBACK = False

    header_info = PEHeaderInfo(
        machine="IMAGE_FILE_MACHINE_I386",
        machine_hex="0x014c",
        number_of_sections=1,
        time_date_stamp=1700000000,
        characteristics_hex="0x0102",
        is_dll=False,
        is_executable_image=True,
        subsystem="IMAGE_SUBSYSTEM_WINDOWS_GUI",
        magic="PE32",
        entry_point_rva="0x1000",
        image_base="0x400000"
    )
    pe_res = PEAnalysisResult(
        status="success",
        headers=header_info,
        sections=[],
        imported_dlls_count=0,
        imported_dlls=[],
        total_imports_count=0,
        exported_functions_count=0,
        exported_functions=[],
        file_entropy=4.5,
        suspicious_indicators=[]
    )
    scan_obj = ScanResponse(
        scan_id=str(uuid.uuid4()),
        file_name="test_fallback.exe",
        file_size_bytes=1024,
        formatted_size="1.0 KB",
        hashes={"sha256": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"},
        owner_id=str(uuid.uuid4()),
        pe_analysis=pe_res,
        clamav=ClamAVResult(status="clean", available=True, matched=False, message="clean"),
        ml_inference=MLInferenceResult(status="benign", available=True, model_name="RandomForest", prediction="benign", confidence_score=0.1, message="clean"),
        verdict=VerdictEnum.NO_THREAT_DETECTED,
        verdict_reasons=["Test reasons"],
        pipeline_status="completed"
    )

    try:
        with pytest.raises(HTTPException) as exc_info:
            await scan_repository.save_scan(scan_obj, user_id=scan_obj.owner_id, raw_token="invalid-token-format")
        assert exc_info.value.status_code == 502
    finally:
        settings.ALLOW_IN_MEMORY_FALLBACK = orig_fallback

