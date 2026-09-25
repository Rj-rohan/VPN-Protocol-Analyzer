from app.security.rules import evaluate_rules
from app.security.scoring import assess_findings


def assess_security(features: dict, inference: dict | None = None) -> dict:
    """Rules read parser features; `inference` (ML predictions) is only used by rules that say so."""
    findings = evaluate_rules({**features, "inference": inference or {}})
    return {"assessment": assess_findings(findings), "findings": findings}
