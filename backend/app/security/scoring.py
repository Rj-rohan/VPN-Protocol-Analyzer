from collections import Counter


SEVERITY_PENALTY = {"Critical": 30, "High": 20, "Medium": 10, "Low": 5}


def assess_findings(findings: list[dict]) -> dict:
    counts = Counter(finding["severity"] for finding in findings)
    penalty = sum(SEVERITY_PENALTY.get(finding["severity"], 0) for finding in findings)
    score = max(0, 100 - penalty)
    if counts["Critical"] or score < 40:
        risk = "Critical"
    elif counts["High"] or score < 70:
        risk = "High"
    elif counts["Medium"] or score < 85:
        risk = "Medium"
    else:
        risk = "Low"
    return {
        "security_score": score,
        "score_name": "Project Security Assessment Score",
        "risk_level": risk,
        "finding_count": len(findings),
        "critical_count": counts["Critical"],
        "high_count": counts["High"],
        "medium_count": counts["Medium"],
        "low_count": counts["Low"],
        "methodology": {
            "baseline": 100,
            "penalties": SEVERITY_PENALTY,
            "formula": "max(0, 100 - sum of triggered finding penalties)",
            "thresholds": {"Low": "85-100 with no Critical or High finding", "Medium": "70-84 or a Medium finding", "High": "40-69 or a High finding", "Critical": "0-39 or any Critical finding"},
            "disclaimer": "This is a project assessment heuristic, not an official security rating or standard.",
        },
    }