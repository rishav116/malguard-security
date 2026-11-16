from fastapi import APIRouter
from app.config import settings
from app.models.schemas import HealthResponse
from app.services.ml_classifier import ml_service
from app.services.diagnostics import get_system_diagnostics

router = APIRouter(tags=["Health"])

@router.get("/health", response_model=HealthResponse)
async def get_health():
    """
    Returns live health telemetry and comprehensive diagnostics for MALGUARD AI detection services.
    Evaluates ClamAV daemon state, cold start timing, memory telemetry, and ML model status.
    """
    diag = get_system_diagnostics(settings.CLAMAV_HOST, settings.CLAMAV_PORT)
    sock = diag.get("clamav_socket", {})
    is_connected = sock.get("connected", False)
    ping_ok = sock.get("ping_ok", False)
    raw_version = sock.get("version")
    socket_err = sock.get("error")

    if is_connected and (ping_ok or raw_version):
        if raw_version and raw_version.startswith("ClamAV ") and "/" in raw_version and "emulator" not in raw_version.lower():
            clamav_desc = f"online (Official {raw_version})"
        elif raw_version:
            clamav_desc = f"online (Development-only EICAR test daemon — NOT production ClamAV: {raw_version})"
        else:
            clamav_desc = "online (Daemon responding, VERSION unverified)"
    else:
<<<<<<< Updated upstream
        if clamav_service.is_starting():
            clamav_desc = "starting / initializing (loading signatures into memory)"
        else:
            failed, fail_reason = clamav_service.is_failed()
            if failed:
                clamav_desc = f"offline / failed ({fail_reason})"
            else:
                clamav_desc = "offline / unavailable"
=======
        if diag["flags"].get("starting") or (diag.get("is_cold_start") and not diag["flags"].get("failed")):
            clamav_desc = f"starting / initializing (loading signatures into memory; uptime: {diag['container_uptime_sec']}s)"
        elif diag["flags"].get("failed"):
            clamav_desc = "offline / failed (clamd process failed during initialization)"
        else:
            clamav_desc = f"offline / unavailable ({socket_err or 'Connection refused'})"
>>>>>>> Stashed changes

    return HealthResponse(
        status="online",
        service=settings.APP_NAME,
        version=settings.APP_VERSION,
        environment=settings.ENVIRONMENT,
        engines={
            "pe_analyzer": "available (pefile static engine)",
            "clamav_daemon": clamav_desc,
            "random_forest_ml": "online / ready (Random Forest v1.0, 69 features)" if ml_service._is_loaded else "model_not_loaded",
        },
        diagnostics=diag
    )

