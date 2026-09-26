from pathlib import Path
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.confidence import compute_confidence
from app.core.audit import audit
from app.core.deps import can_modify, client_ip, get_current_user, get_visible_analysis
from app.core.models import Analysis, Capture, User
from app.core.schemas import AnalysisDetail, AnalysisList, AnalysisSummary, ReportOut
from app.db.database import get_db
from app.db.repositories import dashboard_summary, list_analyses, summary

router = APIRouter(prefix="/api", tags=["analyses"])


@router.get("/analyses", response_model=AnalysisList)
def analyses(
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    risk: str | None = Query(None, pattern="^(Critical|High|Medium|Low)$"),
    status_filter: str | None = Query(None, alias="status", pattern="^(queued|running|completed|failed)$"),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> AnalysisList:
    rows, total = list_analyses(db, user, limit, offset, risk, status_filter)
    return AnalysisList(items=[AnalysisSummary(**summary(row)) for row in rows], total=total, limit=limit, offset=offset)


@router.get("/analyses/{analysis_id}", response_model=AnalysisDetail)
def analysis_detail(request: Request, analysis: Analysis = Depends(get_visible_analysis), user: User = Depends(get_current_user),
                    db: Session = Depends(get_db)) -> AnalysisDetail:
    audit(db, "analysis.view", user, resource_type="analysis", resource_id=analysis.id, ip_address=client_ip(request))
    db.commit()
    capture = analysis.capture
    result = dict(analysis.result or {})
    if result.get("features") and "ai_confidence" not in result:  # analyses stored before the score existed
        result["ai_confidence"] = compute_confidence(result)
    return AnalysisDetail(
        **summary(analysis),
        capture={"id": str(capture.id), "filename": capture.original_filename, "sha256": capture.sha256,
                 "size_bytes": capture.size_bytes, "file_format": capture.file_format,
                 "uploaded_at": capture.created_at.isoformat() if capture.created_at else None},
        warnings=analysis.warnings or [],
        result=result,
        reports=[ReportOut(id=r.id, kind=r.kind, size_bytes=r.size_bytes, narrative_source=r.narrative_source, created_at=r.created_at)
                 for r in sorted(analysis.reports, key=lambda r: r.created_at or 0, reverse=True)],
    )


@router.get("/analyses/{analysis_id}/status")
def analysis_status(analysis: Analysis = Depends(get_visible_analysis)) -> dict:
    return {"analysis_id": str(analysis.id), "status": analysis.status.value, "error": analysis.error_message,
            "started_at": analysis.started_at, "completed_at": analysis.completed_at}


@router.delete("/analyses/{analysis_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_analysis(request: Request, analysis: Analysis = Depends(get_visible_analysis), user: User = Depends(get_current_user),
                    db: Session = Depends(get_db)) -> None:
    """Delete the analysis, its reports and, when no other analysis uses it, the stored capture file."""
    if not can_modify(user, analysis):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Your role does not allow deleting this analysis.")
    capture = analysis.capture
    report_paths = [Path(report.stored_path) for report in analysis.reports]
    db.delete(analysis)
    db.flush()
    remaining = db.scalar(select(Analysis.id).where(Analysis.capture_id == capture.id).limit(1))
    shared_file = db.scalar(select(Capture.id).where(Capture.stored_path == capture.stored_path, Capture.id != capture.id).limit(1))
    delete_file = remaining is None and shared_file is None
    if remaining is None:
        db.delete(capture)
    audit(db, "analysis.delete", user, resource_type="analysis", resource_id=analysis.id, ip_address=client_ip(request),
          detail={"sha256": capture.sha256, "capture_file_deleted": delete_file})
    db.commit()
    for path in report_paths:
        path.unlink(missing_ok=True)
    if delete_file:
        Path(capture.stored_path).unlink(missing_ok=True)


@router.get("/dashboard/summary")
def dashboard(user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> dict:
    return dashboard_summary(db, user)
