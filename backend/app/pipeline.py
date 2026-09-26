"""End-to-end analysis of one capture file.

Deterministic protocol parsing is the source of truth. ML then adds labelled
predictions (traffic category, IPsec mode, ESP cipher family) and the rule
engine re-runs so predicted-evidence findings can be included, each marked
`source: predicted`.
"""
from pathlib import Path

from app.compliance.engine import evaluate_all
from app.confidence import compute_confidence
from app.ml.predict import predict_traffic
from app.ml.protocol_models import predict_protocol
from app.packet.parser import analyze_pcap
from app.security.findings import assess_security


def add_predictions(result: dict) -> dict:
    """Attach ML predictions to a deterministic parser result and re-assess security."""
    features = result["features"]
    result["protocol_inference"] = predict_protocol(features)
    result["traffic_prediction"] = predict_traffic(features)
    result["security"] = assess_security(features, result["protocol_inference"])
    result["compliance"] = evaluate_all(features, result["protocol_inference"])
    result["ai_confidence"] = compute_confidence(result)
    return result


def run_pipeline(path: Path) -> dict:
    return add_predictions(analyze_pcap(path))
