import pandas as pd

from app.dataset_export import CHECKSUMS, assign_splits, describe, sha256, verify
from app.ml.features import FULL_FEATURES, TRAFFIC_CLASSES


def labelled_frame() -> pd.DataFrame:
    rows = []
    for origin, groups in (("linux_xfrm_netns_capture", 8), ("iscx_vpn_2016_openvpn_converted", 6)):
        for g in range(groups):
            for i, label in enumerate(TRAFFIC_CLASSES):
                rows.append({"group": f"{origin}-{g}", "dataset_origin": origin, "traffic_label": label, "packet_count": 10 + i})
    return pd.DataFrame(rows)


def test_every_group_sits_in_one_split_and_one_fold() -> None:
    frame = assign_splits(labelled_frame())
    per_group = frame.groupby("group").agg(splits=("split", "nunique"), folds=("cv_fold", "nunique"))
    assert (per_group["splits"] == 1).all() and (per_group["folds"] == 1).all()
    assert set(frame["cv_fold"]) == {0, 1, 2, 3, 4}
    # The split is made inside each source, so both sources reach the test split.
    assert set(frame.loc[frame["split"] == "test", "dataset_origin"]) == set(frame["dataset_origin"])


def test_every_model_feature_is_described() -> None:
    assert all(describe(name) for name in FULL_FEATURES)


def test_verify_detects_modified_and_missing_files(tmp_path) -> None:
    (tmp_path / "features").mkdir()
    data = tmp_path / "features" / "lab_sessions.csv"
    data.write_text("a,b\n1,2\n", encoding="utf-8")
    (tmp_path / CHECKSUMS).write_text(f"{sha256(data)}  features/lab_sessions.csv\n", encoding="utf-8")
    assert verify(tmp_path) == []
    data.write_text("a,b\n1,3\n", encoding="utf-8")
    assert verify(tmp_path) == ["checksum mismatch: features/lab_sessions.csv"]
    data.unlink()
    assert verify(tmp_path) == ["missing: features/lab_sessions.csv"]
