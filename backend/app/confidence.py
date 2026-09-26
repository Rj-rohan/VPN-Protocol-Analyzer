"""AI Confidence Score: one transparent 0-100 figure for how much of an analysis rests on solid evidence.

The score is the mean of the components that apply to the capture. Each component is reported with
its value and basis so the number can be traced:

* IPsec detection            - evidence-weighted detection confidence
* Configuration evidence     - share of key parameters known (observed 1.0, observed-majority 0.9,
                               inferred 0.8, predicted = confidence x 0.7, not observable 0)
* Traffic classification     - model probability x the model's cross-validated accuracy
* Mode inference             - prediction confidence x measured accuracy (physical rule: 0.99)
* ESP cipher inference       - Bayesian posterior of the chosen layout
"""
from __future__ import annotations

from app.packet.observations import UNKNOWN

METHOD = ("Mean of the applicable components. Each component is a 0-1 estimate of how likely that part of the analysis "
          "is correct; ML components are discounted by the model's measured accuracy. Not a calibrated probability.")
SOURCE_WEIGHT = {"observed": 1.0, "observed-majority": 0.9, "inferred": 0.8}
KEY_PARAMETERS = [
    ("protocol", "ike_version", "IKE version"), ("cryptography", "encryption_algorithm", "encryption"),
    ("cryptography", "integrity_algorithm", "integrity"), ("cryptography", "dh_group", "DH group"),
    ("cryptography", "authentication_method", "authentication"), ("cryptography", "pfs", "PFS"),
    ("", "mode", "mode"), ("sa", "sa_lifetime_seconds", "SA lifetime"), ("sa", "replay_protection", "replay protection"),
    ("sa", "nat_traversal", "NAT-T"), ("sa", "payload_confidentiality", "payload encryption"),
]


def _item(features: dict, section: str, key: str) -> dict:
    item = features.get(section, {}).get(key, {}) if section else features.get(key, {})
    return item if isinstance(item, dict) else {}


def _rekey_measured(features: dict) -> bool:
    return any(_item(features, "sa", key).get("value") not in (UNKNOWN, "Unknown", None)
               for key in ("ike_rekey_interval_seconds", "child_rekey_interval_seconds"))


def compute_confidence(result: dict) -> dict:
    features = result.get("features") or {}
    if not features:
        return {"score": None, "components": [], "method": METHOD}
    inference = result.get("protocol_inference") or {}
    components = []

    detection = features.get("detection", {})
    components.append({"name": "IPsec detection", "value": float(detection.get("confidence", 0.0)), "basis": "heuristic",
                       "explanation": "; ".join(detection.get("evidence", [])) or "No IPsec evidence"})
    if not detection.get("ipsec_detected"):
        return {"score": round(100 * components[0]["value"]), "components": components, "method": METHOD}

    weights, known, unknown = [], [], []
    for section, key, label in KEY_PARAMETERS:
        item = _item(features, section, key)
        value, source = item.get("value"), item.get("source", "unavailable")
        if source in SOURCE_WEIGHT and value not in (UNKNOWN, "Unknown", None):
            weights.append(SOURCE_WEIGHT[source])
            known.append(f"{label} ({source})")
        elif key == "sa_lifetime_seconds" and _rekey_measured(features):
            # IKEv2 never sends lifetimes; measured rekey intervals bound them instead.
            weights.append(SOURCE_WEIGHT["inferred"])
            known.append("SA lifetime (inferred from rekeys)")
        elif key == "mode" and (predicted := inference.get("mode") or {}).get("label"):
            weights.append(0.7 * predicted["confidence"])
            known.append(f"mode (predicted {predicted['confidence']:.0%})")
        else:
            weights.append(0.0)
            unknown.append(label)
    components.append({"name": "Configuration evidence coverage", "value": sum(weights) / len(weights), "basis": "parser",
                       "explanation": f"Known: {', '.join(known) or 'none'}. Not observable: {', '.join(unknown) or 'none'}."})

    traffic = result.get("traffic_prediction") or {}
    if traffic.get("status") == "predicted":
        accuracy = (traffic.get("model") or {}).get("cv_accuracy") or (traffic.get("model") or {}).get("test_metrics", {}).get("accuracy") or 0.0
        components.append({"name": "Traffic classification", "value": traffic["confidence"] * accuracy, "basis": "predicted",
                           "explanation": f"{traffic['label']}: model probability {traffic['confidence']:.0%} x measured accuracy {accuracy:.0%}"})

    mode = inference.get("mode") or {}
    if mode.get("label"):
        accuracy = 0.99 if mode.get("method") == "physical-bound" else (mode.get("cv_accuracy") or 0.0)
        value = mode["confidence"] if mode.get("method") == "physical-bound" else mode["confidence"] * accuracy
        components.append({"name": "Mode inference", "value": value, "basis": "predicted",
                           "explanation": f"{mode['label']}: {mode['confidence']:.0%} via {mode.get('method')}"
                                          + ("" if mode.get("method") == "physical-bound" else f" x measured accuracy {accuracy:.0%}")})

    cipher = inference.get("esp_cipher") or {}
    if cipher.get("label"):
        components.append({"name": "ESP cipher inference", "value": float(cipher["confidence"]), "basis": "predicted",
                           "explanation": f"{cipher['label']}: posterior {cipher['confidence']:.0%} ({cipher.get('method')})"})

    for component in components:
        component["value"] = round(component["value"], 4)
    score = round(100 * sum(c["value"] for c in components) / len(components))
    return {"score": score, "components": components, "method": METHOD}
