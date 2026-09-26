"""Configuration compliance: evaluate an analysis against policy profiles.

A profile is a JSON file with controls; each control names an analysis *field*, an
*operator* and a *value*. Every control ends as:

* pass / fail     - decided from evidence (observed, inferred, or predicted: the basis is reported)
* unknown         - the field is not observable in this capture
* not_applicable  - the control's precondition does not hold (e.g. IKEv1-only checks on IKEv2)

Profiles ship in app/compliance/profiles; more can be added in COMPLIANCE_PROFILE_DIR.
Results are checks derived from the referenced guidance, not a certification.
"""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field, ValidationError

from app.config import settings
from app.packet.observations import UNKNOWN

logger = logging.getLogger(__name__)
BUILTIN_DIR = Path(__file__).parent / "profiles"

DISPLAY_FIELD = {"dh_group_number": "dh_group", "ike_key_bits": "ike_encryption"}
Operator = Literal["equals", "not_equals", "in", "not_in", "min", "max", "is_true", "is_false", "matches", "not_matches"]


class Check(BaseModel):
    field: str
    operator: Operator
    value: Any = None


class Control(BaseModel):
    id: str = Field(max_length=40)
    title: str
    requirement: str
    severity: Literal["Critical", "High", "Medium", "Low"] = "Medium"
    check: Check
    applies_if: Check | None = None
    allow_predicted: bool = True
    reference: str = ""
    remediation: str = ""


class Profile(BaseModel):
    id: str = Field(pattern=r"^[a-z0-9-]{3,60}$")
    name: str
    version: str = "1"
    reference: str = ""
    description: str = ""
    disclaimer: str = "Checks derived from the referenced guidance; not a certification or official assessment."
    controls: list[Control]


def load_profiles() -> dict[str, Profile]:
    directories = [BUILTIN_DIR]
    if settings.compliance_profile_dir:
        directories.append(Path(settings.compliance_profile_dir))
    profiles: dict[str, Profile] = {}
    for directory in directories:
        for path in sorted(directory.glob("*.json")) if directory.exists() else []:
            try:
                profile = Profile.model_validate(json.loads(path.read_text(encoding="utf-8")))
            except (ValidationError, json.JSONDecodeError) as exc:
                logger.warning("Ignoring invalid compliance profile %s: %s", path, exc)
                continue
            profiles[profile.id] = profile
    return profiles


# --- analysis fields ----------------------------------------------------------

def _number(text: Any, pattern: str) -> int | None:
    match = re.search(pattern, str(text))
    return int(match.group(1)) if match else None


def resolve_fields(features: dict, inference: dict | None) -> dict[str, tuple[Any, str, str]]:
    """field name -> (value, basis, evidence). Unobservable fields carry value None."""
    def obs(section: str, key: str) -> tuple[Any, str, str]:
        item = features.get(section, {}).get(key, {}) if section else features.get(key, {})
        value = item.get("value") if isinstance(item, dict) else item
        if value in (UNKNOWN, "Unknown", None, []):
            return None, "unavailable", "; ".join(item.get("evidence", [])) if isinstance(item, dict) else ""
        return value, item.get("source", "observed"), "; ".join(item.get("evidence", [])[:2])

    fields = {
        "ipsec_detected": (features.get("detection", {}).get("ipsec_detected"), "observed", "IPsec detection"),
        "ike_version": obs("protocol", "ike_version"),
        "ike_exchanges": obs("protocol", "ike_exchange_types"),
        "ike_encryption": obs("cryptography", "encryption_algorithm"),
        "ike_integrity": obs("cryptography", "integrity_algorithm"),
        "ike_prf": obs("cryptography", "prf_algorithm"),
        "authentication": obs("cryptography", "authentication_method"),
        "dh_group": obs("cryptography", "dh_group"),
        "pfs": obs("cryptography", "pfs"),
        "sa_lifetime_seconds": obs("sa", "sa_lifetime_seconds"),
        "payload_encrypted": obs("sa", "payload_confidentiality"),
        "nat_traversal": obs("sa", "nat_traversal"),
        "replay_protection": obs("sa", "replay_protection"),
        "mode": obs("", "mode"),
        "child_rekey_interval_seconds": obs("sa", "child_rekey_interval_seconds"),
        "ike_rekey_interval_seconds": obs("sa", "ike_rekey_interval_seconds"),
    }
    # IKEv2 sends no lifetime; an observed IKE rekey interval is the next best evidence of how long keys live.
    lifetime = fields["sa_lifetime_seconds"]
    fields["ike_lifetime_or_rekey_seconds"] = lifetime if lifetime[0] is not None else fields["ike_rekey_interval_seconds"]
    encryption = fields["ike_encryption"]
    fields["ike_key_bits"] = ((_number(encryption[0], r"-(\d{3})\b"), encryption[1], encryption[2]) if encryption[0] else (None, "unavailable", ""))
    dh = fields["dh_group"]
    fields["dh_group_number"] = ((_number(dh[0], r"DH(\d+)"), dh[1], dh[2]) if dh[0] else (None, "unavailable", ""))
    # AI predictions fill fields the parser cannot observe; the basis says "predicted".
    inference = inference or {}
    if fields["mode"][0] is None and (predicted := (inference.get("mode") or {})).get("label"):
        fields["mode"] = (predicted["label"], "predicted", f"AI prediction ({predicted['confidence']:.0%})")
    cipher = inference.get("esp_cipher") or {}
    fields["esp_cipher_family"] = ((cipher["label"], "predicted", f"AI prediction ({cipher['confidence']:.0%}, {cipher.get('method')})")
                                   if cipher.get("label") else (None, "unavailable", cipher.get("reason", "")))
    return fields


def _test(check: Check, value: Any) -> bool:
    op, target = check.operator, check.value
    text = str(value)
    if op == "equals":
        return value == target
    if op == "not_equals":
        return value != target
    if op == "in":
        return value in target
    if op == "not_in":
        return value not in target
    if op == "min":
        return isinstance(value, (int, float)) and value >= target
    if op == "max":
        return isinstance(value, (int, float)) and value <= target
    if op == "is_true":
        return value is True
    if op == "is_false":
        return value is False
    if op == "matches":
        return re.search(target, text, re.IGNORECASE) is not None
    if op == "not_matches":
        return re.search(target, text, re.IGNORECASE) is None
    raise ValueError(op)


def evaluate_profile(profile: Profile, fields: dict[str, tuple[Any, str, str]]) -> dict:
    results = []
    for control in profile.controls:
        entry = {"id": control.id, "title": control.title, "requirement": control.requirement, "severity": control.severity,
                 "reference": control.reference, "remediation": control.remediation, "field": control.check.field}
        if control.applies_if:
            gate_value = fields.get(control.applies_if.field, (None, "unavailable", ""))[0]
            if gate_value is None or not _test(control.applies_if, gate_value):
                results.append({**entry, "status": "not_applicable", "basis": None, "observed": gate_value,
                                "evidence": f"Applies only when {control.applies_if.field} {control.applies_if.operator} {control.applies_if.value}"})
                continue
        value, basis, evidence = fields.get(control.check.field, (None, "unavailable", "Field not produced by the analyzer"))
        if value is None or (basis == "predicted" and not control.allow_predicted):
            status = "unknown"
        else:
            status = "pass" if _test(control.check, value) else "fail"
        # Show the human-readable source value (e.g. "DH2 (MODP-1024)" rather than the derived number 2).
        shown = fields.get(DISPLAY_FIELD.get(control.check.field, control.check.field), (value,))[0]
        if isinstance(shown, list):
            shown = ", ".join(map(str, shown))
        results.append({**entry, "status": status, "basis": basis if value is not None else "unavailable",
                        "observed": shown if value is not None else None, "evidence": evidence or "Not observable in this capture"})
    counts = {s: sum(1 for r in results if r["status"] == s) for s in ("pass", "fail", "unknown", "not_applicable")}
    decided = counts["pass"] + counts["fail"]
    if counts["fail"]:
        verdict = "non-compliant"
    elif counts["unknown"]:
        verdict = "insufficient evidence"
    else:
        verdict = "compliant"
    return {
        "profile": {"id": profile.id, "name": profile.name, "version": profile.version, "reference": profile.reference,
                    "description": profile.description, "disclaimer": profile.disclaimer},
        "verdict": verdict,
        "counts": counts,
        "pass_rate": round(counts["pass"] / decided, 4) if decided else None,
        "failed_by_severity": {level: sum(1 for r in results if r["status"] == "fail" and r["severity"] == level)
                               for level in ("Critical", "High", "Medium", "Low")},
        "controls": results,
    }


def evaluate_all(features: dict, inference: dict | None = None, profile_ids: list[str] | None = None) -> dict:
    fields = resolve_fields(features, inference)
    profiles = load_profiles()
    selected = [profiles[pid] for pid in (profile_ids or profiles) if pid in profiles]
    return {profile.id: evaluate_profile(profile, fields) for profile in selected}
