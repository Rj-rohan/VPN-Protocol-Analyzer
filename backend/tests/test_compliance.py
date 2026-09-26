import json
from pathlib import Path

import pytest

from app.compliance.engine import evaluate_all, load_profiles
from app.config import settings
from app.packet.observations import UNKNOWN
from app.packet.tshark import TSharkService


def obs(value, source="observed"):
    return {"value": value, "source": source, "evidence": ["test"]}


def features(**overrides) -> dict:
    base = {
        "detection": {"ipsec_detected": True},
        "protocol": {"ike_version": obs("IKEv2"), "ike_exchange_types": obs(["IKE_SA_INIT", "IKE_AUTH"])},
        "mode": obs("Unknown", "unavailable"),
        "cryptography": {"encryption_algorithm": obs("AES-256-GCM-16"), "integrity_algorithm": obs("AEAD"),
                         "prf_algorithm": obs("HMAC-SHA2-384"), "authentication_method": obs(UNKNOWN, "unavailable"),
                         "dh_group": obs("DH20 (ECP-384)"), "pfs": obs(UNKNOWN, "unavailable")},
        "sa": {"sa_lifetime_seconds": obs(UNKNOWN, "unavailable"), "payload_confidentiality": obs(True, "inferred"),
               "nat_traversal": obs(False), "replay_protection": obs(UNKNOWN, "unavailable")},
    }
    for path, value in overrides.items():
        section, key = path.split(".")
        base[section][key] = value
    return base


def test_builtin_profiles_load_and_validate() -> None:
    profiles = load_profiles()
    assert {"nist-sp-800-77r1", "cnsa-rfc9206", "org-baseline"} <= set(profiles)
    assert all(profile.controls for profile in profiles.values())


def test_legacy_configuration_fails_nist() -> None:
    legacy = features(**{"protocol.ike_version": obs("IKEv1"), "cryptography.encryption_algorithm": obs("3DES-CBC"),
                         "cryptography.integrity_algorithm": obs("HMAC-SHA1"), "cryptography.dh_group": obs("DH2 (MODP-1024)"),
                         "cryptography.authentication_method": obs("Pre-Shared Key")})
    nist = evaluate_all(legacy, None, ["nist-sp-800-77r1"])["nist-sp-800-77r1"]
    status = {c["id"]: c["status"] for c in nist["controls"]}

    assert nist["verdict"] == "non-compliant"
    assert {status[i] for i in ("NIST-01", "NIST-02", "NIST-03", "NIST-05", "NIST-11")} == {"fail"}
    assert status["NIST-04"] == "not_applicable"  # PRF check applies to IKEv2 only
    assert nist["failed_by_severity"]["High"] >= 3


def test_unobservable_controls_are_unknown_not_passed() -> None:
    nist = evaluate_all(features(), None, ["nist-sp-800-77r1"])["nist-sp-800-77r1"]
    status = {c["id"]: c["status"] for c in nist["controls"]}

    assert status["NIST-06"] == "unknown"  # PFS hidden in encrypted messages
    assert status["NIST-07"] == "unknown"  # IKEv2 sends no lifetime
    assert nist["counts"]["fail"] == 0
    assert nist["verdict"] == "insufficient evidence"


def test_cnsa_distinguishes_strong_from_merely_good() -> None:
    good = features(**{"cryptography.prf_algorithm": obs("HMAC-SHA2-256"), "cryptography.dh_group": obs("DH14 (MODP-2048)")})
    status = {c["id"]: c["status"] for c in evaluate_all(good, None, ["cnsa-rfc9206"])["cnsa-rfc9206"]["controls"]}
    assert status["CNSA-03"] == "fail" and status["CNSA-05"] == "fail"
    strong = {c["id"]: c["status"] for c in evaluate_all(features(), None, ["cnsa-rfc9206"])["cnsa-rfc9206"]["controls"]}
    assert strong["CNSA-01"] == strong["CNSA-02"] == strong["CNSA-03"] == strong["CNSA-05"] == "pass"


def test_ai_predictions_are_used_with_predicted_basis() -> None:
    inference = {"mode": {"label": "Transport", "confidence": 0.91, "method": "random-forest"},
                 "esp_cipher": {"label": "AEAD (AES-GCM or ChaCha20-Poly1305)", "confidence": 0.99, "method": "bayesian-lattice"}}
    org = evaluate_all(features(), inference, ["org-baseline"])["org-baseline"]
    controls = {c["id"]: c for c in org["controls"]}
    assert controls["ORG-05"]["status"] == "fail" and controls["ORG-05"]["basis"] == "predicted"
    assert controls["ORG-07"]["status"] == "pass" and controls["ORG-07"]["basis"] == "predicted"


def test_custom_profile_folder(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "bank.json").write_text(json.dumps({
        "id": "bank-policy", "name": "Bank VPN policy", "controls": [
            {"id": "BANK-01", "title": "No NAT-T", "requirement": "Direct ESP only", "check": {"field": "nat_traversal", "operator": "is_false"}}]}),
        encoding="utf-8")
    (tmp_path / "broken.json").write_text("{not json", encoding="utf-8")
    monkeypatch.setattr(settings, "compliance_profile_dir", str(tmp_path))
    result = evaluate_all(features(), None)
    assert result["bank-policy"]["verdict"] == "compliant"
    assert "broken" not in result


@pytest.mark.skipif(not TSharkService().capabilities().available, reason="TShark is not installed")
def test_compliance_api(api, tmp_path: Path) -> None:
    from test_api import legacy_capture

    analysis_id = api.upload("analyst", legacy_capture(tmp_path)).json()["analysis_id"]
    body = api.client.get(f"/api/analyses/{analysis_id}/compliance", headers=api.as_("analyst")).json()
    assert body["evaluations"]["nist-sp-800-77r1"]["verdict"] == "non-compliant"
    one = api.client.get(f"/api/analyses/{analysis_id}/compliance?profile=cnsa-rfc9206", headers=api.as_("analyst")).json()
    assert list(one["evaluations"]) == ["cnsa-rfc9206"]
    assert api.client.get(f"/api/analyses/{analysis_id}/compliance?profile=nope", headers=api.as_("analyst")).status_code == 404
    assert len(api.client.get("/api/compliance/profiles", headers=api.as_("viewer")).json()["profiles"]) >= 3
