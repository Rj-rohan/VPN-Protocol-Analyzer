from typing import Any

UNKNOWN = "Unknown / Not observable"

# Provenance labels. `predicted` is reserved for ML output and never used by the parser.
OBSERVED = "observed"
OBSERVED_MAJORITY = "observed-majority"
INFERRED = "inferred"
UNAVAILABLE = "unavailable"


def observation(value: Any, source: str, evidence: list[str]) -> dict:
    return {"value": value, "source": source, "evidence": evidence}


def unavailable(*evidence: str) -> dict:
    return observation(UNKNOWN, UNAVAILABLE, list(evidence))
