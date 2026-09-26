import pytest

from app.confidence import compute_confidence
from app.packet.observations import UNKNOWN


def obs(value, source="observed"):
    return {"value": value, "source": source, "evidence": []}


def features(known: bool) -> dict:
    hidden = obs(UNKNOWN, "unavailable")
    return {
        "detection": {"ipsec_detected": True, "confidence": 0.92, "evidence": ["ESP on protocol 50"]},
        "protocol": {"ike_version": obs("IKEv2")},
        "mode": obs("Tunnel", "inferred") if known else obs("Unknown", "unavailable"),
        "cryptography": {"encryption_algorithm": obs("AES-256-GCM-16"), "integrity_algorithm": obs("AEAD"), "dh_group": obs("DH14 (MODP-2048)"),
                         "authentication_method": obs("Pre-Shared Key") if known else hidden, "pfs": obs(True, "inferred") if known else hidden},
        "sa": {"sa_lifetime_seconds": obs(3600) if known else hidden, "replay_protection": hidden, "nat_traversal": obs(False),
               "payload_confidentiality": obs(True, "inferred")},
    }


def test_no_ipsec_scores_detection_only() -> None:
    result = compute_confidence({"features": {"detection": {"ipsec_detected": False, "confidence": 0.0, "evidence": []}}})
    assert result["score"] == 0 and [c["name"] for c in result["components"]] == ["IPsec detection"]


def test_hidden_parameters_lower_the_score() -> None:
    rich = compute_confidence({"features": features(known=True)})
    sparse = compute_confidence({"features": features(known=False)})
    coverage = lambda r: next(c for c in r["components"] if c["name"] == "Configuration evidence coverage")
    assert coverage(rich)["value"] > coverage(sparse)["value"]
    assert "PFS" in coverage(sparse)["explanation"] and rich["score"] > sparse["score"]


def test_measured_rekeys_count_as_an_inferred_lifetime() -> None:
    without = features(known=False)
    with_rekeys = features(known=False)
    with_rekeys["sa"]["child_rekey_interval_seconds"] = obs(18, "inferred")
    coverage = lambda f: next(c for c in compute_confidence({"features": f})["components"] if c["name"] == "Configuration evidence coverage")
    assert coverage(with_rekeys)["value"] > coverage(without)["value"]
    assert "SA lifetime (inferred from rekeys)" in coverage(with_rekeys)["explanation"]


def test_ml_confidence_is_discounted_by_measured_accuracy() -> None:
    result = compute_confidence({
        "features": features(known=True),
        "traffic_prediction": {"status": "predicted", "label": "VoIP", "confidence": 0.99, "model": {"cv_accuracy": 0.77}},
        "protocol_inference": {"mode": {"label": "Transport", "confidence": 0.99, "method": "physical-bound"},
                               "esp_cipher": {"label": "AEAD (AES-GCM or ChaCha20-Poly1305)", "confidence": 1.0, "method": "bayesian-lattice"}},
    })
    components = {c["name"]: c for c in result["components"]}
    assert components["Traffic classification"]["value"] == pytest.approx(0.99 * 0.77, abs=1e-3)
    assert components["Mode inference"]["value"] == pytest.approx(0.99)
    assert components["ESP cipher inference"]["value"] == 1.0
    assert 0 < result["score"] <= 100
