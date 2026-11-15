from fastapi import APIRouter
from app.api.v1.endpoints import health, scans, copilot

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(scans.router)
api_router.include_router(copilot.router, prefix="/copilot")

