"""Evaluate the analyzer against labelled testbed captures.

    python -m app.evaluation                       # data/raw/testbed
    python -m app.evaluation --captures other/dir  # any dir of capture_*.pcap + .json

Writes evaluation_report.json and evaluation_report.md to data/processed/evaluation/.
Analyzer results are cached by pcap SHA-256 so re-runs are fast.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from app.config import REPO_DIR
from app.ml.features import TRAFFIC_CLASSES
from app.ml.protocol_models import family_from_truth
from app.packet.observations import UNKNOWN

DEFAULT_CAPTURES = REPO_DIR / "data" / "raw" / "testbed"
OUTPUT = REPO_DIR / "data" / "processed" / "evaluation"
WEAK_DH = {1, 2, 5, 22, 25}

CRYPTO_FIELDS = {"encryption": "encryption_algorithm", "integrity": "integrity_algorithm", "prf": "prf_algorithm", "dh_group": "dh_group"}


def analyze_cached(pcap: Path) -> dict:
    """Deterministic parser output is cached; ML predictions and rules are always recomputed with the current models."""
    from app.packet.parser import analyze_pcap
    from app.pipeline import add_predictions

    from app.ml.features import FULL_FEATURES

    digest = hashlib.sha256(pcap.read_bytes()).hexdigest()
    # Keyed on the feature set too, so parser output cached before a feature change is not reused.
    from app.packet.esp_structure import ESP_FEATURES

    schema = hashlib.sha256(",".join(FULL_FEATURES + ESP_FEATURES).encode()).hexdigest()[:8]
    cache = OUTPUT / "cache" / f"{digest}-{schema}.json"
    if cache.exists():
        result = json.loads(cache.read_text(encoding="utf-8"))
    else:
        result = analyze_pcap(pcap)
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_text(json.dumps(result, default=str), encoding="utf-8")
    return add_predictions(result)


def expected_rules(truth: dict) -> set[str]:
    """Rules that should fire given the true configuration (independent of what is observable)."""
    ike, child = truth["ike_sa"], truth["child_sa"]
    rules = set()
    if truth["ike_version"] == "IKEv1":
        rules.add("PROTO-001")
    groups = [int(m.group(1)) for value in (ike.get("dh_group"), child.get("dh_group")) if value and (m := re.match(r"DH(\d+)", value))]
    if any(group in WEAK_DH for group in groups):
        rules.add("CRYPTO-001")
    if any(token in (value or "").upper() for value in (ike.get("integrity"), child.get("integrity")) for token in ("SHA1", "MD5")):
        rules.add("CRYPTO-002")
    if child.get("pfs") is False:
        rules.add("CRYPTO-003")
    if any(token in (value or "").upper() for value in (ike.get("encryption"), child.get("encryption")) for token in ("DES", "RC4", "BLOWFISH")):
        rules.add("CRYPTO-004")
    if (child.get("encryption") or "").upper() in ("NULL", "NONE (AH)"):
        rules.add("CRYPTO-005")
    if any(token in (child.get("encryption") or "").upper() for token in ("3DES", "BLOWFISH")):
        rules.add("CRYPTO-006")
    if truth["mode"] == "Transport":
        rules.add("META-001")
    return rules


EVALUATED_RULES = ["PROTO-001", "CRYPTO-001", "CRYPTO-002", "CRYPTO-003", "CRYPTO-004", "CRYPTO-005", "CRYPTO-006", "META-001"]


def _ratio(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 4) if denominator else None


def evaluate(directory: Path) -> dict:
    cases = []
    for truth_path in sorted(directory.glob("capture_*.json")):
        truth = json.loads(truth_path.read_text(encoding="utf-8"))
        pcap = directory / truth["pcap_filename"]
        if pcap.exists():
            cases.append((truth, analyze_cached(pcap)))
    if not cases:
        raise SystemExit(f"No labelled captures in {directory}. Run testbed/scripts/run_testbed.py first.")

    rows = []
    protocol = Counter()
    mode = Counter()
    ai = Counter()
    rekey = Counter()
    crypto = {name: Counter() for name in (*CRYPTO_FIELDS, "pfs", "nat_traversal", "authentication")}
    traffic_pairs: list[tuple[str, str | None]] = []
    rule_counts = {rule: Counter() for rule in EVALUATED_RULES}

    for truth, result in cases:
        features = result["features"]
        row = {"capture_id": truth["capture_id"], "scenario": truth["scenario"], "checks": {}}
        if not truth.get("ipsec_expected", True):
            # Normal-traffic baseline: the only correct answer is "no IPsec".
            detected = features["detection"]["ipsec_detected"]
            protocol["ipsec_detected_correct"] += detected is False
            protocol["ipsec_detected_total"] += 1
            row["checks"]["ipsec_detected"] = {"expected": False, "predicted": detected}
            rows.append(row)
            continue

        for name, predicted, expected in (
            ("ipsec_detected", features["detection"]["ipsec_detected"], True),
            ("ipsec_protocol", features["protocol"]["ipsec_protocol"], truth.get("ipsec_protocol", "ESP")),
            ("ike_version", features["protocol"]["ike_version"]["value"], truth["ike_version"]),
            ("ip_version", features["protocol"]["ip_version"]["value"], truth["ip_version"]),
        ):
            protocol[f"{name}_correct"] += predicted == expected
            protocol[f"{name}_total"] += 1
            row["checks"][name] = {"expected": expected, "predicted": predicted}

        predicted_mode = features["mode"]["value"]
        mode["total"] += 1
        if predicted_mode != "Unknown":
            mode["reported"] += 1
            mode["correct"] += predicted_mode == truth["mode"]
        row["checks"]["mode"] = {"expected": truth["mode"], "predicted": predicted_mode}

        inference = result.get("protocol_inference") or {}
        if inference.get("status") == "predicted":
            ai_mode, ai_cipher = inference["mode"], inference["esp_cipher"]
            expected_family = family_from_truth(truth["child_sa"])
            ai["mode_total"] += 1
            ai["mode_correct"] += ai_mode["label"] == truth["mode"]
            if expected_family:
                ai["cipher_total"] += 1
                if ai_cipher["label"]:
                    ai["cipher_decided"] += 1
                    ai["cipher_correct"] += ai_cipher["label"] == expected_family
            row["checks"]["ai_mode"] = {"expected": truth["mode"], "predicted": ai_mode["label"], "confidence": ai_mode["confidence"]}
            row["checks"]["ai_esp_cipher"] = {"expected": expected_family, "predicted": ai_cipher["label"], "confidence": ai_cipher["confidence"]}
        else:
            ai["unavailable"] += 1

        comparisons = {name: (features["cryptography"][field]["value"], truth["ike_sa"].get(name)) for name, field in CRYPTO_FIELDS.items()}
        comparisons["pfs"] = (features["cryptography"]["pfs"]["value"], truth["pfs"])
        comparisons["nat_traversal"] = (features["sa"]["nat_traversal"]["value"], truth["nat_traversal"])
        comparisons["authentication"] = (features["cryptography"]["authentication_method"]["value"], truth.get("authentication"))
        for name, (predicted, expected) in comparisons.items():
            if expected is None:
                continue
            counter = crypto[name]
            if predicted in (UNKNOWN, "Unknown"):
                counter["fn"] += 1
            elif predicted == expected:
                counter["tp"] += 1
            else:
                counter["fp"] += 1
            row["checks"][name] = {"expected": expected, "predicted": predicted}

        if truth.get("child_rekey_seconds"):
            inferred = features["sa"].get("child_rekey_interval_seconds", {}).get("value")
            rekey["total"] += 1
            if isinstance(inferred, (int, float)):
                rekey["reported"] += 1
                rekey["correct"] += abs(inferred - truth["child_rekey_seconds"]) <= max(3, 0.2 * truth["child_rekey_seconds"])
            row["checks"]["child_rekey_interval"] = {"expected": truth["child_rekey_seconds"], "predicted": inferred}

        prediction = result.get("traffic_prediction") or {}
        traffic_pairs.append((truth["traffic"], prediction.get("label")))
        row["checks"]["traffic"] = {"expected": truth["traffic"], "predicted": prediction.get("label"), "confidence": prediction.get("confidence")}

        fired = {finding["rule_id"] for finding in result["security"]["findings"]}
        expected = expected_rules(truth)
        for rule in EVALUATED_RULES:
            key = ("t" if (rule in fired) == (rule in expected) else "f") + ("p" if rule in fired else "n")
            rule_counts[rule][key] += 1
        row["rules"] = {"expected": sorted(expected), "fired": sorted(fired)}
        rows.append(row)

    predicted_labels = [p for _, p in traffic_pairs if p]
    labels = [label for label in TRAFFIC_CLASSES if label in {t for t, _ in traffic_pairs} | set(predicted_labels)]
    per_class = {}
    for label in labels:
        tp = sum(1 for t, p in traffic_pairs if t == label and p == label)
        fp = sum(1 for t, p in traffic_pairs if t != label and p == label)
        fn = sum(1 for t, p in traffic_pairs if t == label and p != label)
        precision, recall = _ratio(tp, tp + fp), _ratio(tp, tp + fn)
        f1 = round(2 * precision * recall / (precision + recall), 4) if precision and recall else 0.0
        per_class[label] = {"precision": precision, "recall": recall, "f1": f1, "support": tp + fn}
    confusion = [[sum(1 for t, p in traffic_pairs if t == truth_label and p == predicted_label) for predicted_label in labels] for truth_label in labels]

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "captures": len(cases),
        "source": str(directory),
        "protocol_identification": {name: _ratio(protocol[f"{name}_correct"], protocol[f"{name}_total"])
                                    for name in ("ipsec_detected", "ipsec_protocol", "ike_version", "ip_version")},
        "rekey_inference": {"child_interval_accuracy": _ratio(rekey["correct"], rekey["reported"]),
                            "reported": rekey["reported"], "captures_with_rekeys": rekey["total"]},
        "mode_detection": {"accuracy_when_reported": _ratio(mode["correct"], mode["reported"]), "coverage": _ratio(mode["reported"], mode["total"]),
                           "reported": mode["reported"], "total": mode["total"]},
        "field_extraction": {name: {**dict(c), "precision": _ratio(c["tp"], c["tp"] + c["fp"]), "recall": _ratio(c["tp"], c["tp"] + c["fn"])}
                             for name, c in crypto.items()},
        "ai_protocol_inference": {
            "mode_accuracy": _ratio(ai["mode_correct"], ai["mode_total"]), "mode_predictions": ai["mode_total"],
            "esp_cipher_accuracy_when_decided": _ratio(ai["cipher_correct"], ai["cipher_decided"]),
            "esp_cipher_coverage": _ratio(ai["cipher_decided"], ai["cipher_total"]), "esp_cipher_decided": ai["cipher_decided"],
            "esp_cipher_predictions": ai["cipher_total"],
            "unavailable": ai["unavailable"],
        },
        "traffic_classification": {
            "accuracy": _ratio(sum(1 for t, p in traffic_pairs if t == p), len(traffic_pairs)),
            "predicted": len(predicted_labels), "total": len(traffic_pairs),
            "per_class": per_class, "confusion_matrix": {"labels": labels, "matrix": confusion},
        },
        "security_rules": {rule: {k: c.get(k, 0) for k in ("tp", "fp", "tn", "fn")} for rule, c in rule_counts.items()},
        "per_capture": rows,
    }


def markdown(report: dict) -> str:
    fmt = lambda v: "n/a" if v is None else f"{v:.1%}"
    lines = [f"# Analyzer evaluation ({report['captures']} labelled captures)", "", f"Generated {report['generated_at']} from `{report['source']}`.", "",
             "## Protocol identification", "", "| Check | Accuracy |", "|---|---|",
             *(f"| {name} | {fmt(value)} |" for name, value in report["protocol_identification"].items()), "",
             "## Mode detection", "",
             f"Accuracy when a mode is reported: {fmt(report['mode_detection']['accuracy_when_reported'])}; reported for "
             f"{report['mode_detection']['reported']} of {report['mode_detection']['total']} captures (the rest are encrypted ESP, where mode is not observable).", "",
             "## Rekey inference", "",
             f"Child SA rekey interval within 20% of the configured timer: {fmt(report['rekey_inference']['child_interval_accuracy'])} "
             f"({report['rekey_inference']['reported']} of {report['rekey_inference']['captures_with_rekeys']} rekeying captures reported an interval).", "",
             "## AI protocol inference (predicted from ESP packet lengths)", "",
             f"Tunnel/transport mode: {fmt(report['ai_protocol_inference']['mode_accuracy'])} of {report['ai_protocol_inference']['mode_predictions']} captures; "
             f"ESP cipher family: {fmt(report['ai_protocol_inference']['esp_cipher_accuracy_when_decided'])} correct when decided, decided for "
             f"{report['ai_protocol_inference']['esp_cipher_decided']} of {report['ai_protocol_inference']['esp_cipher_predictions']} "
             "(constant-size traffic is left undecided); "
             f"not enough ESP packets: {report['ai_protocol_inference']['unavailable']}.", "",
             "## Field extraction", "", "Unknown counts as a false negative (not observable), never as correct.", "",
             "| Field | TP | FP | FN | Precision | Recall |", "|---|---|---|---|---|---|",
             *(f"| {name} | {v.get('tp', 0)} | {v.get('fp', 0)} | {v.get('fn', 0)} | {fmt(v['precision'])} | {fmt(v['recall'])} |" for name, v in report["field_extraction"].items()), "",
             "## Security rules", "", "| Rule | TP | FP | TN | FN |", "|---|---|---|---|---|",
             *(f"| {rule} | {c['tp']} | {c['fp']} | {c['tn']} | {c['fn']} |" for rule, c in report["security_rules"].items()), "",
             "## Traffic classification", "",
             f"Accuracy {fmt(report['traffic_classification']['accuracy'])} ({report['traffic_classification']['predicted']} of {report['traffic_classification']['total']} captures received a prediction).", ""]
    matrix = report["traffic_classification"]["confusion_matrix"]
    if matrix["labels"]:
        lines += ["| truth \\ predicted | " + " | ".join(matrix["labels"]) + " |", "|---" * (len(matrix["labels"]) + 1) + "|",
                  *(f"| {label} | " + " | ".join(map(str, row)) + " |" for label, row in zip(matrix["labels"], matrix["matrix"]))]
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--captures", type=Path, default=DEFAULT_CAPTURES)
    args = parser.parse_args()
    report = evaluate(args.captures)
    OUTPUT.mkdir(parents=True, exist_ok=True)
    (OUTPUT / "evaluation_report.json").write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    (OUTPUT / "evaluation_report.md").write_text(markdown(report), encoding="utf-8")
    print(markdown(report))


if __name__ == "__main__":
    main()
