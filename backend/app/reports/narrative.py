"""Human-readable narrative built only from structured analyzer output.

`facts()` is the single input to both the deterministic template below and the
optional LLM layer, so every statement about the configuration traces back to
parser or rule-engine output.
"""
from __future__ import annotations

from app.config import settings
from app.packet.observations import UNKNOWN

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def _value(observation) -> object:
    return observation.get("value") if isinstance(observation, dict) else observation


def _display(value) -> str:
    if value is True:
        return "Yes"
    if value is False:
        return "No"
    if isinstance(value, list):
        return ", ".join(map(str, value)) or UNKNOWN
    return str(value)


def facts(result: dict, filename: str) -> dict:
    """Compact, structured summary of one analysis: the only input the narrative layers may use."""
    features = result.get("features", {})
    crypto, sa, protocol = features.get("cryptography", {}), features.get("sa", {}), features.get("protocol", {})
    assessment = result.get("security", {}).get("assessment", {})
    findings = sorted(result.get("security", {}).get("findings", []), key=lambda f: SEVERITY_ORDER.get(f["severity"], 9))
    prediction = result.get("traffic_prediction") or {}
    traffic = features.get("traffic", {}).get("features", {})
    inference = result.get("protocol_inference") or {}

    def inferred(target: str) -> dict:
        entry = inference.get(target) or {}
        return {"value": entry.get("label"), "confidence": entry.get("confidence"), "source": "predicted"} if entry.get("label") else \
               {"value": None, "confidence": None, "source": "unavailable"}

    def field(observation: dict) -> dict:
        return {"value": _display(_value(observation)), "source": observation.get("source", "unavailable") if isinstance(observation, dict) else "observed"}

    return {
        "capture": {"filename": filename, "packet_count": result.get("packet_count", 0), "protocols": result.get("detected_protocols", [])},
        "detection": {key: features.get("detection", {}).get(key) for key in ("ipsec_detected", "ike_detected", "esp_detected", "ah_detected", "confidence")},
        "configuration": {
            "ipsec_protocol": {"value": protocol.get("ipsec_protocol", UNKNOWN), "source": "observed"},
            "ike_version": field(protocol.get("ike_version", {})),
            "ike_exchanges": field(protocol.get("ike_exchange_types", {})),
            "ip_version": field(protocol.get("ip_version", {})),
            "mode": field(features.get("mode", {})),
            "encryption": field(crypto.get("encryption_algorithm", {})),
            "integrity": field(crypto.get("integrity_algorithm", {})),
            "prf": field(crypto.get("prf_algorithm", {})),
            "authentication": field(crypto.get("authentication_method", {})),
            "dh_group": field(crypto.get("dh_group", {})),
            "pfs": field(crypto.get("pfs", {})),
            "sa_lifetime_seconds": field(sa.get("sa_lifetime_seconds", {})),
            "ike_rekey_interval_seconds": field(sa.get("ike_rekey_interval_seconds", {})),
            "child_rekey_interval_seconds": field(sa.get("child_rekey_interval_seconds", {})),
            "nat_traversal": field(sa.get("nat_traversal", {})),
            "replay_protection": field(sa.get("replay_protection", {})),
            "payload_confidentiality": field(sa.get("payload_confidentiality", {})),
            "crypto_scope": crypto.get("scope", UNKNOWN),
        },
        "ai_inference": {"mode": inferred("mode"), "esp_cipher": inferred("esp_cipher")},
        "ai_confidence": {"score": (result.get("ai_confidence") or {}).get("score"),
                          "components": {c["name"]: round(c["value"], 2) for c in (result.get("ai_confidence") or {}).get("components", [])}},
        # Default profile first: the executive summary sentence uses it.
        "compliance": {pid: {"profile": e["profile"]["name"], "verdict": e["verdict"], "counts": e["counts"],
                             "failed": [c["id"] + " " + c["title"] for c in e["controls"] if c["status"] == "fail"]}
                       for pid, e in sorted((result.get("compliance") or {}).items(),
                                            key=lambda item: item[0] != settings.default_compliance_profile)},
        "assessment": {key: assessment.get(key) for key in ("security_score", "risk_level", "finding_count", "critical_count", "high_count", "medium_count", "low_count")},
        "findings": [{key: f[key] for key in ("rule_id", "title", "severity", "evidence", "impact", "recommendation")} for f in findings],
        "traffic": {
            "esp_packets": traffic.get("flow_packet_count", 0),
            "duration_seconds": round(traffic.get("duration_seconds", 0.0), 2),
            "packets_per_second": round(traffic.get("packets_per_second", 0.0), 2),
            "avg_packet_size_bytes": round(traffic.get("avg_packet_size_bytes", 0.0), 1),
            "uplink_ratio": round(traffic.get("uplink_ratio", 0.0), 3),
            "predicted_category": prediction.get("label"),
            "prediction_confidence": prediction.get("confidence"),
            "prediction_status": prediction.get("status", "unavailable"),
            "model_training_source": (prediction.get("model") or {}).get("training_source"),
        },
    }


def _lifetime_text(cfg: dict) -> str:
    """The negotiated lifetime (IKEv1), or else the rekey intervals measured in the capture (IKEv2 never sends lifetimes)."""
    if cfg["sa_lifetime_seconds"]["value"] not in (UNKNOWN, "Unknown"):
        return f"{cfg['sa_lifetime_seconds']['value']} s [{cfg['sa_lifetime_seconds']['source']}]"
    measured = [f"{label} rekey every {cfg[key]['value']} s" for key, label in
                (("ike_rekey_interval_seconds", "IKE SA"), ("child_rekey_interval_seconds", "child SA"))
                if cfg.get(key, {}).get("value") not in (None, UNKNOWN, "Unknown")]
    return f"{', '.join(measured)} [inferred from rekeys]" if measured else cfg["sa_lifetime_seconds"]["value"]


def _unknown_fields(f: dict) -> list[str]:
    labels = {"ike_version": "IKE version", "mode": "IPsec mode", "encryption": "encryption", "integrity": "integrity",
              "authentication": "authentication method", "dh_group": "DH group", "pfs": "PFS", "replay_protection": "replay protection"}
    return [label for key, label in labels.items() if f["configuration"][key]["value"] in (UNKNOWN, "Unknown")]


def template_narrative(f: dict) -> dict:
    cfg, assessment, findings, traffic = f["configuration"], f["assessment"], f["findings"], f["traffic"]
    if not f["detection"]["ipsec_detected"]:
        summary = (f"The capture {f['capture']['filename']} ({f['capture']['packet_count']} packets) contains no IKE, ESP or AH traffic, "
                   "so no IPsec configuration could be assessed.")
        return {"executive_summary": summary, "technical_explanation": summary, "remediation": [], "limitations": _limitations(f)}

    top = [x for x in findings if x["severity"] in ("Critical", "High")]
    summary = [
        f"The capture {f['capture']['filename']} contains IPsec traffic ({cfg['ipsec_protocol']['value']}) negotiated with "
        f"{cfg['ike_version']['value']}. The Project Security Assessment Score is {assessment['security_score']}/100, "
        f"which the project methodology rates as {assessment['risk_level']} risk.",
    ]
    if top:
        summary.append(f"{len(top)} critical or high finding(s) need attention, led by: " + "; ".join(x["title"] for x in top[:3]) + ".")
    else:
        summary.append("No critical or high-severity weaknesses were observed in the parameters visible on the wire.")
    for check in f.get("compliance", {}).values():
        failed = check["counts"]["fail"]
        summary.append(f"Against {check['profile']} the configuration is {check['verdict']}"
                       + (f" ({failed} failed control(s))." if failed else "."))
        break  # the default profile comes first; all profiles are listed in the reports
    unknown = _unknown_fields(f)
    if unknown:
        summary.append(f"Some parameters are not observable from encrypted traffic ({', '.join(unknown)}); they must be confirmed on the VPN endpoints.")
    if traffic["prediction_status"] == "predicted":
        summary.append(f"Traffic patterns most resemble {traffic['predicted_category']} (model probability {traffic['prediction_confidence']:.0%}); "
                       "this is a statistical inference, not a decryption result.")

    technical = [
        f"Negotiation: {cfg['ike_version']['value']} ({cfg['ike_exchanges']['value']}). IKE SA transforms ({cfg['crypto_scope']}): "
        f"encryption {cfg['encryption']['value']} [{cfg['encryption']['source']}], integrity {cfg['integrity']['value']} [{cfg['integrity']['source']}], "
        f"PRF {cfg['prf']['value']}, DH group {cfg['dh_group']['value']} [{cfg['dh_group']['source']}], authentication {cfg['authentication']['value']}.",
        f"Encapsulation: mode {cfg['mode']['value']} [{cfg['mode']['source']}], outer {cfg['ip_version']['value']}, NAT-T {cfg['nat_traversal']['value']}, "
        f"payload encrypted: {cfg['payload_confidentiality']['value']}. PFS: {cfg['pfs']['value']} [{cfg['pfs']['source']}]. SA lifetime: {_lifetime_text(cfg)}. "
        f"Replay protection: {cfg['replay_protection']['value']}.",
        f"Traffic: {traffic['esp_packets']} ESP/AH packets over {traffic['duration_seconds']} s ({traffic['packets_per_second']} packets/s, "
        f"average {traffic['avg_packet_size_bytes']} bytes, uplink share {traffic['uplink_ratio']:.0%}).",
    ]
    ai = f.get("ai_inference", {})
    predicted = [f"{name} {entry['value']} ({entry['confidence']:.0%})" for name, entry in
                 (("mode", ai.get("mode", {})), ("ESP cipher family", ai.get("esp_cipher", {}))) if entry.get("value")]
    if predicted:
        technical.append("AI inference from ESP packet lengths (predicted, not observed): " + "; ".join(predicted) + ".")
    for finding in findings:
        technical.append(f"[{finding['severity']}] {finding['rule_id']} {finding['title']}: {finding['evidence']}")
    remediation = []
    for finding in findings:
        if finding["recommendation"] not in remediation:
            remediation.append(finding["recommendation"])
    return {"executive_summary": " ".join(summary), "technical_explanation": "\n".join(technical), "remediation": remediation,
            "limitations": _limitations(f)}


def _limitations(f: dict) -> list[str]:
    items = [
        "Payloads are not decrypted; the analysis uses cleartext IKE negotiation, packet headers, sizes and timing only.",
        "Cryptographic values describe the IKE SA seen in cleartext; ESP child SA transforms are negotiated inside encrypted messages and may differ.",
        "The Project Security Assessment Score is a transparent project heuristic, not an official security rating or standard.",
    ]
    if f["traffic"]["prediction_status"] == "predicted":
        items.append("Traffic categories are probabilistic predictions from encrypted-traffic metadata and can be wrong.")
        if (f["traffic"]["model_training_source"] or "").startswith("synthetic"):
            items.append("The traffic model was trained on synthetic lab statistics and has not been validated on real captures.")
    return items
