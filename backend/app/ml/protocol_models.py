"""AI inference of IPsec mode and ESP cipher family from encrypted packet lengths.

    python -m app.ml.protocol_models      # train the mode model and evaluate both on the lab sessions

* ESP cipher family: Bayesian length-lattice inference (app.packet.esp_structure). It needs
  no training data; the lab sessions are used only to measure its accuracy.
* Tunnel vs transport mode: a RandomForest on cipher-normalised inner-packet sizes plus
  traffic context, with one physical rule. An inner packet smaller than 28 bytes cannot
  carry an IPv4 header plus a transport header, so it proves transport mode.

AES-128 and AES-256 produce identical packet sizes, so key length is never inferred. Outputs
are labelled `predicted` and never replace observed values. ISCX windows are excluded:
their ESP framing was synthesised, so they carry no real cipher or mode signal.
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock

import numpy as np
import pandas as pd

from app.config import settings
from app.ml.features import FULL_FEATURES
from app.packet.esp_structure import ESP_FEATURES, LAYOUTS, MIN_PACKETS, NULL_FAMILY

AEAD, CBC_SHA1, CBC_SHA256, CBC64_SHA1 = list(LAYOUTS)
CIPHER_FAMILIES = (*LAYOUTS, NULL_FAMILY)
MODES = ("Tunnel", "Transport")
MODE_FEATURES = ESP_FEATURES + FULL_FEATURES
TUNNEL_MIN_INNER = 28  # IPv4 header (20) + the smallest transport header (UDP/ICMP, 8)
MODEL_FILE = "protocol_inference.joblib"
SEED = 26160
KEY_LENGTH_NOTE = "Key length (AES-128 vs AES-256) is not observable: both produce identical packet sizes."
CAVEAT = ("Predicted from ESP packet-length patterns (padding block, IV and ICV sizes; inner-header overhead). "
          "Nothing is decrypted. Observed IKE values and cleartext evidence always take precedence.")


def family_from_proposal(proposal: str | None) -> str | None:
    """Cipher family from a session label (Linux XFRM profile cipher or strongSwan ESP proposal)."""
    p = (proposal or "").lower()
    if "gcm" in p or "chacha" in p:
        return AEAD
    if p.startswith("null"):
        return NULL_FAMILY
    if "3des" in p or "blowfish" in p:
        return CBC64_SHA1
    if "sha1" in p:
        return CBC_SHA1
    if "sha256" in p:
        return CBC_SHA256
    return None


def family_from_truth(child_sa: dict) -> str | None:
    """Cipher family from testbed ground truth (child SA encryption + integrity)."""
    encryption, integrity = (child_sa.get("encryption") or "").upper(), (child_sa.get("integrity") or "").upper()
    if not encryption or encryption.startswith("NONE"):  # AH: no ESP cipher to infer
        return None
    if "GCM" in encryption or "CHACHA" in encryption:
        return AEAD
    if encryption == "NULL":
        return NULL_FAMILY
    if "3DES" in encryption or "BLOWFISH" in encryption:
        return CBC64_SHA1
    if "SHA1" in integrity:
        return CBC_SHA1
    if "SHA2-256" in integrity:
        return CBC_SHA256
    return None


# --- inference --------------------------------------------------------------

def infer_cipher(structure: dict) -> dict:
    cipher = structure.get("cipher") or {}
    if cipher.get("status") == "ambiguous":
        return {"label": None, "confidence": None, "method": "bayesian-lattice",
                "reason": f"Only {structure['summary']['distinct_lengths']} distinct ESP lengths; layouts cannot be distinguished",
                "probabilities": cipher.get("posterior", {}), "key_length": KEY_LENGTH_NOTE}
    confidence = cipher["posterior"].get(cipher["family"], 1.0)
    method = "readable-payload" if cipher.get("status") == "readable" else "bayesian-lattice"
    return {"label": cipher["family"], "confidence": round(confidence, 4), "method": method,
            "probabilities": cipher["posterior"], "layout": cipher.get("layout"), "key_length": KEY_LENGTH_NOTE}


def physically_transport(measured: dict) -> bool:
    """The smallest inner packet cannot hold an IPv4 header plus a transport header (layout must be decided)."""
    return measured.get("esp_layout_decided") == 1.0 and measured.get("esp_inner_upper_min", 1e9) < TUNNEL_MIN_INNER


def infer_mode(structure: dict, traffic_features: dict, artifact: dict | None) -> dict:
    inner_upper_bound = structure["features"]["esp_inner_upper_min"]
    if physically_transport(structure["features"]):
        return {"label": "Transport", "confidence": 0.99, "method": "physical-bound",
                "probabilities": {"Transport": 0.99, "Tunnel": 0.01},
                "reason": f"Smallest inner packet is at most {inner_upper_bound:.0f} bytes, too small to hold an IPv4 header plus a transport header"}
    if artifact is None:
        return {"label": None, "confidence": None, "method": "unavailable", "reason": "No mode model; run `python -m app.ml.protocol_models`"}
    row = {**traffic_features, **structure["features"]}
    frame = pd.DataFrame([{name: row.get(name, np.nan) for name in artifact["mode_features"]}])
    model = artifact["mode_model"]
    ranked = sorted(zip(model.classes_, map(float, model.predict_proba(frame)[0])), key=lambda item: -item[1])
    return {"label": str(ranked[0][0]), "confidence": round(ranked[0][1], 4), "method": "random-forest",
            "probabilities": {str(k): round(v, 4) for k, v in ranked}, "cv_accuracy": artifact.get("mode_cv_accuracy")}


def _evidence(structure: dict) -> list[str]:
    s, cipher = structure["summary"], structure.get("cipher") or {}
    layout = cipher.get("layout") or {}
    lines = [f"{structure['measured_packets']} ESP payload lengths measured ({s['distinct_lengths']} distinct); "
             f"{s['dominant_residue_share']:.0%} are ≡ {s['dominant_residue_mod16']} (mod 16)"]
    if cipher.get("status") == "readable":
        lines.append(f"{s['readable_fraction']:.0%} of ESP payloads parse as cleartext headers (ESP-NULL)")
    elif layout:
        lines.append(f"Best-fitting layout: {layout['iv_bytes']}-byte IV, {layout['padding_block']}-byte padding block, "
                     f"{layout['icv_bytes']}-byte ICV")
    lines.append(f"Smallest ESP payload {s['smallest_payload']} bytes, so the smallest inner packet is about {s['smallest_inner_estimate']} bytes "
                 "(tunnel mode adds a 20-byte IPv4 / 40-byte IPv6 inner header)")
    return lines


_cache: dict[str, tuple[float, dict]] = {}
_lock = Lock()


def load_model(directory: Path | None = None) -> dict | None:
    path = (directory or settings.model_dir) / MODEL_FILE
    if not path.exists():
        return None
    with _lock:
        mtime = path.stat().st_mtime
        if (cached := _cache.get(str(path))) and cached[0] == mtime:
            return cached[1]
        import joblib

        artifact = joblib.load(path)
        _cache[str(path)] = (mtime, artifact)
        return artifact


def predict_protocol(features: dict, directory: Path | None = None) -> dict:
    from app.ml.features import from_traffic_metadata

    structure = features.get("esp_structure") or {}
    if not structure.get("features"):
        return {"status": "unavailable", "source": "unavailable",
                "reason": structure.get("note") or f"Fewer than {MIN_PACKETS} measurable ESP packets", "caveat": CAVEAT}
    artifact = load_model(directory)
    traffic = from_traffic_metadata(features.get("traffic", {}).get("features", {}))
    return {
        "status": "predicted", "source": "predicted",
        "model_version": artifact["version"] if artifact else None,
        "esp_cipher": infer_cipher(structure),
        "mode": infer_mode(structure, traffic, artifact),
        "evidence": _evidence(structure),
        "caveat": CAVEAT,
    }


# --- training and measurement -----------------------------------------------

def load_training_frame() -> pd.DataFrame:
    from app.ml.preprocessing import load_sessions
    from app.ml.train import DATA_DIR, SESSIONS_DIR

    frame, _ = load_sessions(SESSIONS_DIR, cache=DATA_DIR / "processed" / "traffic_sessions_features.csv")
    frame["cipher_family"] = frame["esp_proposal"].map(family_from_proposal)
    return frame.dropna(subset=["esp_inner_min"])  # sessions with too few ESP packets carry no lattice


def train(out_dir: Path | None = None) -> dict:
    import joblib
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import StratifiedGroupKFold

    from app.ml.preprocessing import GROUP, LABEL
    from app.ml.train import scores

    out_dir = out_dir or settings.model_dir
    frame = load_training_frame()
    data = frame.dropna(subset=["mode"]).assign(**{LABEL: lambda d: d["mode"]})
    build = lambda: RandomForestClassifier(n_estimators=400, min_samples_leaf=2, class_weight="balanced", random_state=SEED, n_jobs=-1)
    folds = min(5, data[GROUP].nunique())
    predicted = pd.Series(index=data.index, dtype=object)
    for train_index, test_index in StratifiedGroupKFold(n_splits=folds, shuffle=True, random_state=SEED).split(data, data[LABEL], data[GROUP]):
        model = build().fit(data.iloc[train_index][MODE_FEATURES], data.iloc[train_index][LABEL])
        predicted.iloc[test_index] = model.predict(data.iloc[test_index][MODE_FEATURES])
    # Measure the deployed behaviour: the physical rule decides first, the model handles the rest.
    by_rule = data.apply(lambda row: physically_transport(row.to_dict()), axis=1)
    predicted[by_rule] = "Transport"
    mode_cv = scores(data, predicted.to_numpy(), MODES)
    mode_cv["decided_by_physical_rule"] = int(by_rule.sum())
    mode_model = build().fit(data[MODE_FEATURES], data[LABEL])

    trained_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    artifact = {"version": f"protocol-{trained_at[:19].replace(':', '').replace('-', '')}", "trained_at": trained_at,
                "mode_model": mode_model, "mode_features": MODE_FEATURES, "mode_cv_accuracy": round(mode_cv["accuracy"], 4)}
    metrics = {
        "trained_at": trained_at,
        "mode": {"rows": int(len(data)), "profiles": int(data[GROUP].nunique()), "folds": folds, "cross_validation": mode_cv,
                 "class_counts": {k: int(v) for k, v in data[LABEL].value_counts().items()},
                 "top_feature_importances": dict(sorted(zip(MODE_FEATURES, map(float, mode_model.feature_importances_)), key=lambda i: -i[1])[:8])},
        "esp_cipher": measure_cipher(frame),
    }
    archive = out_dir / "versions" / artifact["version"]
    for directory in (out_dir, archive):
        directory.mkdir(parents=True, exist_ok=True)
        joblib.dump(artifact, directory / MODEL_FILE)
        (directory / "protocol_inference_metrics.json").write_text(json.dumps(metrics, indent=2, default=str), encoding="utf-8")
    return metrics


def measure_cipher(frame: pd.DataFrame) -> dict:
    """Accuracy of the training-free Bayesian cipher inference on the labelled sessions."""
    labelled = frame.dropna(subset=["cipher_family"])
    results = pd.DataFrame({"truth": labelled["cipher_family"], "predicted": labelled["esp_cipher_inferred"]})
    decided = results.dropna(subset=["predicted"])
    per_class = {family: {"sessions": int((results["truth"] == family).sum()),
                          "decided": int((decided["truth"] == family).sum()),
                          "correct": int(((decided["truth"] == family) & (decided["predicted"] == family)).sum())}
                 for family in CIPHER_FAMILIES if (results["truth"] == family).any()}
    return {"sessions": int(len(results)), "decided": int(len(decided)),
            "accuracy_when_decided": float((decided["truth"] == decided["predicted"]).mean()) if len(decided) else None,
            "coverage": float(len(decided) / len(results)) if len(results) else None, "per_class": per_class}


def main() -> None:
    argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter).parse_args()
    metrics = train()
    mode = metrics["mode"]
    cv = mode["cross_validation"]
    print(f"Mode: {mode['rows']} sessions from {mode['profiles']} VPN profiles; {mode['folds']}-fold group CV accuracy {cv['accuracy']:.3f} "
          f"(recall " + ", ".join(f"{k} {v['recall']:.2f}" for k, v in cv["per_class"].items()) + f"); "
          f"{cv['decided_by_physical_rule']} decided by the physical bound")
    cipher = metrics["esp_cipher"]
    print(f"ESP cipher (Bayesian, no training): accuracy {cipher['accuracy_when_decided']:.3f} on {cipher['decided']} sessions; "
          f"decided for {cipher['coverage']:.0%} (the rest have too few distinct lengths)")
    for family, info in cipher["per_class"].items():
        print(f"   {family}: {info['correct']}/{info['decided']} correct ({info['sessions']} sessions)")
    print(f"Saved {settings.model_dir / MODEL_FILE}")


if __name__ == "__main__":
    main()
