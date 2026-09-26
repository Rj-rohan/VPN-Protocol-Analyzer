from pathlib import Path

import pandas as pd
import pytest

from app.ml.features import BASE_FEATURES, FULL_FEATURES, from_traffic_metadata
from app.ml.predict import MIN_PACKETS, predict_traffic
from app.ml.preprocessing import GROUP, LABEL, group_split, load_synthetic, validate
from app.ml.train import SYNTHETIC_CSV


def test_synthetic_dataset_validates() -> None:
    frame, report = load_synthetic(SYNTHETIC_CSV)
    assert report.ok, report.errors
    assert report.rows == 2000
    assert report.groups == 100
    assert set(report.class_counts) == {"Web", "Video", "VoIP", "Email", "Chat", "ICMP", "File-Transfer"}


def test_validation_catches_bad_rows() -> None:
    frame = pd.DataFrame([{**{f: 1.0 for f in BASE_FEATURES}, "uplink_ratio": 1.5, LABEL: "Gaming", GROUP: "g1"}])
    report = validate(frame, BASE_FEATURES)
    assert not report.ok
    assert any("uplink_ratio" in error for error in report.errors)
    assert any("Gaming" in error for error in report.errors)


def test_group_split_never_shares_a_configuration() -> None:
    frame, _ = load_synthetic(SYNTHETIC_CSV)
    splits = group_split(frame)
    groups = {name: set(part[GROUP]) for name, part in splits.items()}
    assert not groups["train"] & groups["validation"]
    assert not groups["train"] & groups["test"]
    assert not groups["validation"] & groups["test"]
    assert sum(len(part) for part in splits.values()) == len(frame)
    assert (len(groups["train"]), len(groups["validation"]), len(groups["test"])) == (70, 15, 15)


def test_feature_mapping_covers_every_model_feature() -> None:
    vector = from_traffic_metadata({"flow_packet_count": 42, "avg_packet_size_bytes": 512.0})
    assert set(vector) == set(FULL_FEATURES)
    assert vector["packet_count"] == 42.0


def test_prediction_refuses_tiny_flows() -> None:
    result = predict_traffic({"traffic": {"features": {"flow_packet_count": MIN_PACKETS - 1}}})
    assert result["status"] == "unavailable"
    assert result["label"] is None


def test_prediction_without_model(tmp_path: Path) -> None:
    result = predict_traffic({"traffic": {"features": {"flow_packet_count": 500}}}, directory=tmp_path)
    assert result["status"] == "unavailable"
    assert "train" in result["reason"]


@pytest.mark.skipif(not (SYNTHETIC_CSV.parent / "models" / "traffic_classifier_synthetic.joblib").exists(), reason="model not trained")
def test_prediction_is_labelled_and_caveated() -> None:
    features = {name: 1.0 for name in FULL_FEATURES}
    features.update({"flow_packet_count": 120, "avg_packet_size_bytes": 95.0, "avg_interarrival_ms": 2500.0, "duration_seconds": 240.0})
    result = predict_traffic({"traffic": {"features": features}})
    assert result["status"] == "predicted"
    assert result["source"] == "predicted"
    assert abs(sum(result["probabilities"].values()) - 1.0) < 0.01
    assert "not decrypted" in result["caveat"]
    if result["model"]["training_source"].startswith("synthetic"):
        assert "synthetic" in result["caveat"]
