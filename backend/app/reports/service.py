from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from app.compliance.engine import evaluate_all
from app.confidence import compute_confidence
from app.config import settings
from app.core.models import Analysis, Report, ReportKind, User
from app.reports import executive, llm, technical
from app.reports.narrative import facts, template_narrative


def current_result(analysis: Analysis) -> dict:
    """Stored result with compliance re-evaluated against today's profiles."""
    result = dict(analysis.result or {})
    if result.get("features"):
        result["compliance"] = evaluate_all(result["features"], result.get("protocol_inference"))
        result["ai_confidence"] = compute_confidence(result)
    return result


def narrative_for(analysis: Analysis, use_llm: bool) -> tuple[dict, dict, str]:
    """Return (facts, narrative, source). Falls back to the deterministic template whenever the LLM is unavailable or rejected."""
    f = facts(current_result(analysis), analysis.capture.original_filename)
    template = template_narrative(f)
    if use_llm:
        generated, note = llm.generate(f)
        if generated:
            return f, {**generated, "limitations": template["limitations"]}, note
        return f, template, f"deterministic template ({note})"
    return f, template, "deterministic template"


def generate_report(analysis: Analysis, kind: ReportKind, user: User) -> Report:
    f, narrative, source = narrative_for(analysis, use_llm=True)
    meta = {
        "filename": analysis.capture.original_filename, "sha256": analysis.capture.sha256, "size_bytes": analysis.capture.size_bytes,
        "analysis_id": str(analysis.id),
        # The database may return local time; convert so the "UTC" label is true.
        "completed_at": analysis.completed_at.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC") if analysis.completed_at else "n/a",
    }
    if kind == ReportKind.executive:
        content = executive.build(f, narrative, source, meta)
    else:
        content = technical.build(f, narrative, source, meta, current_result(analysis))
    settings.report_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    path = settings.report_dir / f"{analysis.id}_{kind.value}_{stamp}.pdf"
    path.write_bytes(content)
    return Report(analysis_id=analysis.id, kind=kind, stored_path=str(path), sha256=hashlib.sha256(content).hexdigest(),
                  size_bytes=len(content), narrative_source=source[:128], generated_by_id=user.id)
