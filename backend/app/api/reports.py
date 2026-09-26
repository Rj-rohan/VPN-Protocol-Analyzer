from pathlib import Path
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.audit import audit
from app.core.deps import can_view, client_ip, get_current_user, get_visible_analysis
from app.core.models import Analysis, AnalysisStatus, AuditLog, Report, Role, User
from app.core.schemas import ReportOut, ReportRequest
from app.db.database import get_db
from app.reports.llm import llm_available
from app.reports.service import generate_report, narrative_for

router = APIRouter(prefix="/api", tags=["reports"])


def _completed(analysis: Analysis) -> Analysis:
    if analysis.status != AnalysisStatus.completed:
        raise HTTPException(status.HTTP_409_CONFLICT, "Reports are available once the analysis has completed.")
    return analysis


@router.get("/analyses/{analysis_id}/narrative")
def narrative(analysis: Analysis = Depends(get_visible_analysis), use_llm: bool = Query(False, alias="llm")) -> dict:
    """Executive/technical explanation as JSON for the dashboard."""
    f, text, source = narrative_for(_completed(analysis), use_llm=use_llm)
    return {"narrative": text, "source": source, "llm_available": llm_available(), "facts": f}


@router.post("/analyses/{analysis_id}/reports", response_model=ReportOut, status_code=status.HTTP_201_CREATED)
def create_report(body: ReportRequest, request: Request, analysis: Analysis = Depends(get_visible_analysis),
                  user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> ReportOut:
    report = generate_report(_completed(analysis), body.kind, user)
    db.add(report)
    db.flush()
    audit(db, "report.generate", user, resource_type="report", resource_id=report.id, ip_address=client_ip(request),
          detail={"analysis_id": str(analysis.id), "kind": body.kind.value, "narrative_source": report.narrative_source})
    db.commit()
    return ReportOut(id=report.id, kind=report.kind, size_bytes=report.size_bytes, narrative_source=report.narrative_source, created_at=report.created_at)


@router.get("/reports/{report_id}/download")
def download_report(report_id: UUID, request: Request, user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> FileResponse:
    report = db.get(Report, report_id)
    if not report or not can_view(user, report.analysis):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Report not found.")
    path = Path(report.stored_path)
    if not path.is_file():
        raise HTTPException(status.HTTP_410_GONE, "The report file is no longer available; generate it again.")
    audit(db, "report.download", user, resource_type="report", resource_id=report.id, ip_address=client_ip(request))
    db.commit()
    filename = f"ipsec-{report.kind.value}-report-{str(report.analysis_id)[:8]}.pdf"
    return FileResponse(path, media_type="application/pdf", filename=filename, headers={"Cache-Control": "no-store"})


@router.get("/audit")
def audit_log(limit: int = Query(100, ge=1, le=500), user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> list[dict]:
    if user.role != Role.admin:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Only administrators can read the audit log.")
    rows = db.scalars(select(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit)).all()
    return [{"id": str(r.id), "user_id": str(r.user_id) if r.user_id else None, "action": r.action, "resource_type": r.resource_type,
             "resource_id": r.resource_id, "ip_address": r.ip_address, "outcome": r.outcome, "detail": r.detail,
             "created_at": r.created_at.isoformat() if r.created_at else None} for r in rows]
