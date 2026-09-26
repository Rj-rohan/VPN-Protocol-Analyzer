from app.security.findings import assess_security


def observation(value, source="observed"):
    return {"value": value, "source": source, "evidence": ["test fixture"]}


def test_security_assessment_reports_transparent_high_risk_findings() -> None:
    features = {
        "protocol": {"ike_version": observation("IKEv1")},
        "cryptography": {
            "encryption_algorithm": observation("3DES-CBC"),
            "integrity_algorithm": observation("HMAC-SHA1-96"),
            "authentication_method": observation("RSA"),
            "dh_group": observation("DH5"),
            "pfs": observation(False),
        },
        "sa": {
            "replay_protection": observation(False),
            "sa_lifetime_seconds": observation(172800),
        },
    }

    result = assess_security(features)
    findings = result["findings"]
    rule_ids = {finding["rule_id"] for finding in findings}

    assert {"PROTO-001", "CRYPTO-001", "CRYPTO-002", "CRYPTO-003", "CRYPTO-004", "SA-001", "SA-002"} <= rule_ids
    assert all({"rule_id", "severity", "condition", "evidence", "impact", "recommendation", "source"} <= finding.keys() for finding in findings)
    assert result["assessment"]["security_score"] == 0
    assert result["assessment"]["risk_level"] == "Critical"


def test_unknown_parameters_are_reported_without_claiming_security() -> None:
    result = assess_security({
        "detection": {"ipsec_detected": True},
        "protocol": {"ike_version": observation("Unknown / Not observable", "unavailable")},
        "cryptography": {
            "encryption_algorithm": observation("Unknown / Not observable", "unavailable"),
            "integrity_algorithm": observation("Unknown / Not observable", "unavailable"),
            "authentication_method": observation("Unknown / Not observable", "unavailable"),
            "dh_group": observation("Unknown / Not observable", "unavailable"),
            "pfs": observation("Unknown / Not observable", "unavailable"),
        },
        "sa": {"replay_protection": observation("Unknown / Not observable", "unavailable")},
    })

    assert result["assessment"]["risk_level"] == "Low"
    assert result["assessment"]["low_count"] == 1
    assert result["findings"][0]["rule_id"] == "OBS-001"


def test_capture_without_ipsec_has_no_ipsec_findings() -> None:
    unknown = observation("Unknown / Not observable", "unavailable")
    result = assess_security({
        "detection": {"ipsec_detected": False},
        "protocol": {"ike_version": unknown},
        "cryptography": {"encryption_algorithm": unknown, "pfs": unknown},
        "sa": {"replay_protection": unknown},
    })

    assert result["findings"] == []


def test_clean_observable_configuration_has_no_findings() -> None:
    result = assess_security({
        "protocol": {"ike_version": observation("IKEv2")},
        "cryptography": {
            "encryption_algorithm": observation("AES-256-GCM"),
            "integrity_algorithm": observation("AEAD"),
            "authentication_method": observation("ECDSA"),
            "dh_group": observation("DH19"),
            "pfs": observation(True),
        },
        "sa": {"replay_protection": observation(True), "sa_lifetime_seconds": observation(3600)},
    })

    assert result["findings"] == []
    assert result["assessment"]["security_score"] == 100
    assert result["assessment"]["risk_level"] == "Low"