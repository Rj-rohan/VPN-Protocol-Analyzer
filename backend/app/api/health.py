from fastapi import APIRouter

from app.config import settings
from app.packet.tshark import TSharkService

router = APIRouter(tags=["health"])


@router.get("/health")
def health() -> dict:
    return {"status": "ok", "service": settings.app_name, "tshark": TSharkService().availability()}