import hashlib
import logging
import re
from pathlib import Path
from uuid import uuid4

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile, status
from sqlalchemy.orm import Session

from app.config import settings
from app.core.audit import audit
from app.core.deps import client_ip, require_roles
from app.core.models import Role, User
from app.core.schemas import UploadResponse
from app.db.database import get_db
from app.db.repositories import create_analysis, create_capture
from app.worker import get_queue

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/captures", tags=["captures"])
SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]")

# Leading bytes of libpcap (both byte orders, micro- and nanosecond) and pcapng files.
MAGIC = {
    b"\xd4\xc3\xb2\xa1": "pcap", b"\xa1\xb2\xc3\xd4": "pcap",
    b"\x4d\x3c\xb2\xa1": "pcap", b"\xa1\xb2\x3c\x4d": "pcap",
    b"\x0a\x0d\x0d\x0a": "pcapng",
}


def safe_filename(filename: str) -> str:
    # Keep only the final path component and a conservative character set: no traversal, no hidden files.
    name = SAFE_NAME.sub("_", Path(filename.replace("\\", "/")).name).lstrip(".")
    return name[:180] or "capture.pcap"


@router.post("/upload", response_model=UploadResponse, status_code=status.HTTP_202_ACCEPTED)
async def upload_capture(
    request: Request,
    file: UploadFile = File(...),
    user: User = Depends(require_roles(Role.analyst, Role.admin)),
    db: Session = Depends(get_db),
) -> UploadResponse:
    filename = file.filename or "capture.pcap"
    if Path(filename).suffix.lower() not in settings.allowed_extension_set:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Only {', '.join(sorted(settings.allowed_extension_set))} files are accepted.")
    settings.storage_dir.mkdir(parents=True, exist_ok=True)
    safe_name = safe_filename(filename)
    temp_path = settings.storage_dir / f".upload-{uuid4().hex}.part"
    stored_path: Path | None = None
    created_file = False
    digest = hashlib.sha256()
    size = 0
    file_format = None
    try:
        with temp_path.open("wb") as destination:
            while chunk := await file.read(1024 * 1024):
                if file_format is None:
                    file_format = MAGIC.get(chunk[:4])
                    if file_format is None:
                        raise HTTPException(status.HTTP_400_BAD_REQUEST, "File content is not a pcap or pcapng capture.")
                size += len(chunk)
                if size > settings.max_upload_size_bytes:
                    raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "Capture exceeds the configured size limit.")
                digest.update(chunk)
                destination.write(chunk)
        if size == 0:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "The uploaded file is empty.")
        # Content-addressed name: identical uploads share one file, different uploads never collide.
        stored_path = settings.storage_dir / f"{digest.hexdigest()[:16]}_{safe_name}"
        created_file = not stored_path.exists()
        if created_file:
            temp_path.replace(stored_path)
        capture = create_capture(db, user, filename[:255], stored_path, digest.hexdigest(), size, file_format)
        analysis = create_analysis(db, capture)
        audit(db, "capture.upload", user, resource_type="analysis", resource_id=analysis.id, ip_address=client_ip(request),
              detail={"filename": filename[:255], "sha256": digest.hexdigest(), "size_bytes": size})
        db.commit()
    except HTTPException as exc:
        db.rollback()
        audit(db, "capture.upload", user, ip_address=client_ip(request), outcome="rejected", detail={"filename": filename[:255], "reason": exc.detail})
        db.commit()
        raise
    except Exception:
        db.rollback()
        if created_file and stored_path is not None:
            stored_path.unlink(missing_ok=True)
        logger.exception("Capture upload failed")
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Capture could not be stored.")
    finally:
        temp_path.unlink(missing_ok=True)

    get_queue().enqueue(analysis.id)
    db.refresh(analysis)
    return UploadResponse(analysis_id=analysis.id, capture_id=capture.id, filename=filename[:255], sha256=digest.hexdigest(),
                          size_bytes=size, status=analysis.status)
