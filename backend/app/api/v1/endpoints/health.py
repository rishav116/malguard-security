from fastapi import APIRouter
from app.config import settings
from app.models.schemas import HealthResponse
from app.services.clamav_scanner import clamav_service
from app.services.ml_classifier import ml_service

router = APIRouter(tags=["Health"])

@router.get("/health", response_model=HealthResponse)
def get_health():
    """
    Returns live health telemetry for MALGUARD AI detection services.
    """
    is_online, is_official, version_info = clamav_service.verify_daemon_engine()

    if is_online:
        if is_official:
            clamav_desc = f"online (Official {version_info})"
        else:
            clamav_desc = f"online (Development-only EICAR test daemon — NOT production ClamAV: {version_info})"
    else:
        clamav_desc = "offline / unavailable"

    return HealthResponse(
        status="online",
        service=settings.APP_NAME,
        version=settings.APP_VERSION,
        environment=settings.ENVIRONMENT,
        engines={
            "pe_analyzer": "available (pefile static engine)",
            "clamav_daemon": clamav_desc,
            "random_forest_ml": "online / ready (Random Forest v1.0, 69 features)" if ml_service._is_loaded else "model_not_loaded",
        }
    )
