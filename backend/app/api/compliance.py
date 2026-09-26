from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.compliance.engine import evaluate_all, load_profiles
from app.config import settings
from app.core.deps import get_current_user, get_visible_analysis
from app.core.models import Analysis, AnalysisStatus, User

router = APIRouter(prefix="/api", tags=["compliance"])


@router.get("/compliance/profiles")
def profiles(user: User = Depends(get_current_user)) -> dict:
    return {
        "default": settings.default_compliance_profile,
        "profiles": [{"id": p.id, "name": p.name, "version": p.version, "reference": p.reference, "description": p.description,
                      "controls": len(p.controls)} for p in load_profiles().values()],
    }


@router.get("/analyses/{analysis_id}/compliance")
def analysis_compliance(analysis: Analysis = Depends(get_visible_analysis), profile: str | None = Query(None, max_length=60)) -> dict:
    """Re-evaluated from the stored analysis, so profiles added or edited later apply to earlier captures."""
    if analysis.status != AnalysisStatus.completed:
        raise HTTPException(status.HTTP_409_CONFLICT, "Compliance is available once the analysis has completed.")
    result = analysis.result or {}
    evaluations = evaluate_all(result.get("features", {}), result.get("protocol_inference"), [profile] if profile else None)
    if profile and profile not in evaluations:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Unknown compliance profile.")
    return {"default": settings.default_compliance_profile, "evaluations": evaluations}
