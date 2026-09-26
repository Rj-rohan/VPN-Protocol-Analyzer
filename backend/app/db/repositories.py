from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.models import (
    Analysis, AnalysisStatus, Capture, IpsecConfiguration, Role, SecurityFindingRecord, TrafficPrediction, User,
)


def create_capture(db: Session, owner: User | None, filename: str, path: Path, sha256: str, size: int, file_format: str) -> Capture:
    capture = Capture(owner_id=owner.id if owner else None, original_filename=filename, stored_path=str(path),
                      sha256=sha256, size_bytes=size, file_format=file_format)
    db.add(capture)
    db.flush()
    return capture


def create_analysis(db: Session, capture: Capture) -> Analysis:
    analysis = Analysis(capture_id=capture.id, status=AnalysisStatus.queued)
    db.add(analysis)
    db.flush()
    return analysis


def get_analysis(db: Session, analysis_id: UUID) -> Analysis | None:
    return db.get(Analysis, analysis_id)


def mark_running(analysis: Analysis) -> None:
    analysis.status = AnalysisStatus.running
    analysis.started_at = datetime.now(timezone.utc)
    analysis.error_message = None


def _text(observation: dict | str | None) -> str:
    value = observation.get("value") if isinstance(observation, dict) else observation
    if isinstance(value, list):
        return ", ".join(map(str, value))
    return str(value)


def complete_analysis(db: Session, analysis: Analysis, result: dict) -> None:
    features = result["features"]
    security = result["security"]
    prediction = result.get("traffic_prediction") or {}
    crypto, sa, protocol = features["cryptography"], features["sa"], features["protocol"]

    analysis.status = AnalysisStatus.completed
    analysis.packet_count = result["packet_count"]
    analysis.detected_protocols = result["detected_protocols"]
    analysis.ipsec_detected = features["detection"]["ipsec_detected"]
    analysis.security_score = security["assessment"]["security_score"]
    analysis.risk_level = security["assessment"]["risk_level"]
    analysis.predicted_traffic = prediction.get("label")
    analysis.tshark_version = result.get("tshark_version")
    analysis.warnings = result.get("warnings", [])
    analysis.result = result
    analysis.completed_at = datetime.now(timezone.utc)

    lifetime = sa["sa_lifetime_seconds"]["value"]
    analysis.configuration = IpsecConfiguration(
        ipsec_protocol=protocol["ipsec_protocol"], ike_version=_text(protocol["ike_version"]), mode=_text(features["mode"]),
        ip_version=_text(protocol["ip_version"]), encryption_algorithm=_text(crypto["encryption_algorithm"]),
        integrity_algorithm=_text(crypto["integrity_algorithm"]), prf_algorithm=_text(crypto["prf_algorithm"]),
        authentication_method=_text(crypto["authentication_method"]), dh_group=_text(crypto["dh_group"]), pfs=_text(crypto["pfs"]),
        sa_lifetime_seconds=lifetime if isinstance(lifetime, int) else None, nat_traversal=_text(sa["nat_traversal"]),
        replay_protection=_text(sa["replay_protection"]),
        observations={"protocol": protocol, "mode": features["mode"], "cryptography": crypto, "sa": sa},
    )
    analysis.findings = [SecurityFindingRecord(**{key: finding[key] for key in (
        "rule_id", "title", "severity", "condition", "evidence", "impact", "recommendation", "source")}) for finding in security["findings"]]
    if prediction.get("status") == "predicted":
        analysis.predictions = [TrafficPrediction(
            model_name=prediction["model"]["name"], model_version=prediction["model"]["version"],
            predicted_label=prediction["label"], confidence=prediction["confidence"],
            probabilities=prediction["probabilities"], features=prediction["features_used"],
        )]


def fail_analysis(analysis: Analysis, message: str) -> None:
    analysis.status = AnalysisStatus.failed
    analysis.error_message = message
    analysis.completed_at = datetime.now(timezone.utc)


def visible_analyses(db: Session, user: User):
    query = select(Analysis).join(Capture)
    if user.role == Role.analyst:
        query = query.where(Capture.owner_id == user.id)
    return query


def list_analyses(db: Session, user: User, limit: int, offset: int, risk: str | None = None, status: str | None = None) -> tuple[list[Analysis], int]:
    query = visible_analyses(db, user)
    if risk:
        query = query.where(Analysis.risk_level == risk)
    if status:
        query = query.where(Analysis.status == AnalysisStatus(status))
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = db.scalars(query.order_by(Analysis.created_at.desc()).limit(limit).offset(offset)).all()
    return list(rows), total


def dashboard_summary(db: Session, user: User) -> dict:
    analyses = list(db.scalars(visible_analyses(db, user).order_by(Analysis.created_at.desc())).all())
    completed = [a for a in analyses if a.status == AnalysisStatus.completed]
    ids = [a.id for a in completed]
    findings = list(db.scalars(select(SecurityFindingRecord).where(SecurityFindingRecord.analysis_id.in_(ids))).all()) if ids else []
    severity = Counter(f.severity for f in findings)
    return {
        "total_analyses": len(analyses),
        "completed_analyses": len(completed),
        "failed_analyses": sum(1 for a in analyses if a.status == AnalysisStatus.failed),
        "pending_analyses": sum(1 for a in analyses if a.status in (AnalysisStatus.queued, AnalysisStatus.running)),
        "ipsec_detections": sum(1 for a in completed if a.ipsec_detected),
        "high_risk_captures": sum(1 for a in completed if a.risk_level in ("High", "Critical")),
        "critical_findings": severity.get("Critical", 0),
        "findings_by_severity": {level: severity.get(level, 0) for level in ("Critical", "High", "Medium", "Low")},
        "risk_distribution": {level: sum(1 for a in completed if a.risk_level == level) for level in ("Critical", "High", "Medium", "Low")},
        "traffic_categories": dict(Counter(a.predicted_traffic for a in completed if a.predicted_traffic)),
        "top_findings": [{"rule_id": rule, "title": title, "count": count}
                         for (rule, title), count in Counter((f.rule_id, f.title) for f in findings).most_common(6)],
        "ike_versions": dict(Counter(a.configuration.ike_version for a in completed if a.configuration)),
        "compliance": _compliance_overview(completed),
        "average_ai_confidence": _average([((a.result or {}).get("ai_confidence") or {}).get("score") for a in completed]),
        "average_score": round(sum(a.security_score for a in completed if a.security_score is not None) / len(completed), 1) if completed else None,
        "recent": [summary(a) for a in analyses[:8]],
    }


def _average(values: list) -> float | None:
    numbers = [v for v in values if isinstance(v, (int, float))]
    return round(sum(numbers) / len(numbers), 1) if numbers else None


def _compliance_overview(completed: list[Analysis]) -> dict:
    from app.config import settings

    profile = settings.default_compliance_profile
    evaluations = [(a.result or {}).get("compliance", {}).get(profile) for a in completed]
    evaluations = [e for e in evaluations if e]
    verdicts = Counter(e["verdict"] for e in evaluations)
    return {
        "profile": profile,
        "profile_name": evaluations[0]["profile"]["name"] if evaluations else profile,
        "verdicts": {v: verdicts.get(v, 0) for v in ("compliant", "insufficient evidence", "non-compliant")},
        "top_failed_controls": [{"id": cid, "title": title, "count": n} for (cid, title), n in
                                Counter((c["id"], c["title"]) for e in evaluations for c in e["controls"] if c["status"] == "fail").most_common(5)],
    }


def summary(analysis: Analysis) -> dict:
    return {
        "analysis_id": str(analysis.id),
        "filename": analysis.capture.original_filename,
        "status": analysis.status.value,
        "packet_count": analysis.packet_count,
        "detected_protocols": analysis.detected_protocols or [],
        "ipsec_detected": analysis.ipsec_detected,
        "security_score": analysis.security_score,
        "risk_level": analysis.risk_level,
        "predicted_traffic": analysis.predicted_traffic,
        "ike_version": analysis.configuration.ike_version if analysis.configuration else None,
        "error": analysis.error_message,
        "created_at": analysis.created_at.isoformat() if analysis.created_at else None,
        "completed_at": analysis.completed_at.isoformat() if analysis.completed_at else None,
        "owner": analysis.capture.owner.email if analysis.capture.owner else None,
    }
