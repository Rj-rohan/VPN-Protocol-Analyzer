from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.config import settings
from app.core.audit import audit
from app.core.deps import client_ip, get_current_user
from app.core.models import User
from app.db.database import get_db
from app.live import FILTERS, LiveCaptureError, dumpcap_executable, list_interfaces, manager

router = APIRouter(prefix="/api/live", tags=["live capture"])


def allowed(user: User = Depends(get_current_user)) -> User:
    roles = {r.strip() for r in settings.live_capture_roles.split(",") if r.strip()}
    if user.role.value not in roles:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Live capture is not enabled for your role.")
    return user


class StartRequest(BaseModel):
    interface: str = Field(max_length=512)
    duration_seconds: int = Field(ge=5, le=3600)
    filter: str = Field(default="ipsec", pattern="^(ipsec|all)$")


@router.get("/status")
def live_status(user: User = Depends(allowed)) -> dict:
    active = manager.active
    return {"available": dumpcap_executable() is not None, "max_seconds": settings.live_capture_max_seconds,
            "max_megabytes": settings.live_capture_max_megabytes, "filters": list(FILTERS),
            "active": active.as_dict() if active else None}


@router.get("/interfaces")
def interfaces(user: User = Depends(allowed)) -> list[dict]:
    try:
        return list_interfaces()
    except LiveCaptureError as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc))


@router.post("/sessions", status_code=status.HTTP_201_CREATED)
def start(body: StartRequest, request: Request, user: User = Depends(allowed), db: Session = Depends(get_db)) -> dict:
    try:
        session = manager.start(user, body.interface, body.duration_seconds, body.filter)
    except LiveCaptureError as exc:
        audit(db, "live.start", user, ip_address=client_ip(request), outcome="rejected", detail={"reason": str(exc)[:200]})
        db.commit()
        raise HTTPException(status.HTTP_409_CONFLICT if "already running" in str(exc) else status.HTTP_400_BAD_REQUEST, str(exc))
    audit(db, "live.start", user, resource_type="live", resource_id=session.id, ip_address=client_ip(request),
          detail={"interface": session.interface_label, "seconds": session.duration_seconds, "filter": session.capture_filter})
    db.commit()
    return session.as_dict()


def _visible(session_id: UUID, user: User):
    session = manager.sessions.get(session_id)
    if not session or (session.user_id != user.id and user.role.value != "admin"):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Live capture not found.")
    return session


@router.get("/sessions/{session_id}")
def get_session(session_id: UUID, user: User = Depends(allowed)) -> dict:
    return _visible(session_id, user).as_dict()


@router.post("/sessions/{session_id}/stop")
def stop(session_id: UUID, request: Request, user: User = Depends(allowed), db: Session = Depends(get_db)) -> dict:
    session = _visible(session_id, user)
    if session.status == "capturing":
        manager.stop(session)
        audit(db, "live.stop", user, resource_type="live", resource_id=session.id, ip_address=client_ip(request))
        db.commit()
    return session.as_dict()
