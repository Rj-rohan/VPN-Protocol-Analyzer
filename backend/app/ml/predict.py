"""Probabilistic traffic-class inference from encrypted-traffic metadata."""
from __future__ import annotations

import logging
from pathlib import Path
from threading import Lock

from app.config import settings
from app.ml.features import from_traffic_metadata

logger = logging.getLogger(__name__)

MODELS_DIR = settings.model_dir
# A model trained on real testbed captures is preferred over the synthetic scaffold.
MODEL_CANDIDATES = (
    "traffic_classifier_combined.joblib",   # lab ESP sessions + real-app ISCX windows
    "traffic_classifier_testbed.joblib",    # lab ESP sessions
    "traffic_classifier_iscx.joblib",       # ISCX only
    "traffic_classifier_synthetic.joblib",  # supplied synthetic CSV (scaffolding)
)
MIN_PACKETS = 10
CAVEAT = ("Probabilistic inference from packet sizes, timing and direction of encrypted traffic. "
          "Payloads are not decrypted; the true application cannot be identified with certainty.")

_cache: dict[str, tuple[float, dict]] = {}
_lock = Lock()


def load_model(directory: Path = MODELS_DIR) -> dict | None:
    for name in MODEL_CANDIDATES:
        path = directory / name
        if not path.exists():
            continue
        mtime = path.stat().st_mtime
        with _lock:
            cached = _cache.get(str(path))
            if cached and cached[0] == mtime:
                return cached[1]
            try:
                import joblib

                artifact = joblib.load(path)
            except Exception as exc:  # corrupt or incompatible artifact: fall through to the next candidate
                logger.warning("Cannot load traffic model %s: %s", path, exc)
                continue
            _cache[str(path)] = (mtime, artifact)
            return artifact
    return None


def unavailable(reason: str) -> dict:
    return {"status": "unavailable", "source": "unavailable", "label": None, "confidence": None, "reason": reason, "caveat": CAVEAT}


def predict_traffic(features: dict, directory: Path = MODELS_DIR) -> dict:
    traffic = features.get("traffic", {}).get("features", {})
    packets = traffic.get("flow_packet_count", 0)
    if packets < MIN_PACKETS:
        return unavailable(f"Only {packets} ESP/AH packet(s) observed; at least {MIN_PACKETS} are needed for traffic classification")
    artifact = load_model(directory)
    if artifact is None:
        return unavailable("No trained traffic model is available; run `python -m app.ml.train`")

    import pandas as pd

    vector = from_traffic_metadata(traffic)
    frame = pd.DataFrame([{name: vector[name] for name in artifact["features"]}])
    probabilities = artifact["model"].predict_proba(frame)[0]
    labels = artifact["encoder"].inverse_transform(list(range(len(probabilities))))
    ranked = sorted(zip(labels, map(float, probabilities)), key=lambda item: -item[1])
    caveats = [CAVEAT]
    if artifact["training_source"].startswith("synthetic"):
        caveats.append("This model was trained on synthetic lab statistics and has not been validated on real captures.")
    return {
        "status": "predicted",
        "source": "predicted",
        "label": ranked[0][0],
        "confidence": round(ranked[0][1], 4),
        "confidence_note": "Model class probability; not a calibrated likelihood.",
        "probabilities": {label: round(probability, 4) for label, probability in ranked},
        "model": {
            "name": artifact["model_name"], "version": artifact["version"], "training_source": artifact["training_source"],
            "trained_at": artifact["trained_at"], "test_metrics": artifact.get("test_metrics", {}),
            "cv_accuracy": artifact.get("cv_accuracy"),
            "cv_accuracy_by_source": artifact.get("cv_accuracy_by_source", {}),
        },
        "features_used": {name: round(vector[name], 4) for name in artifact["features"]},
        "caveat": " ".join(caveats),
    }
