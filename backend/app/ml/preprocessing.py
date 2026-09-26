"""Dataset loading, validation and leakage-safe splitting."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
import pandas as pd

from app.ml.features import BASE_FEATURES, FULL_FEATURES, TRAFFIC_CLASSES, from_traffic_metadata

LABEL = "traffic_label"
GROUP = "group"


@dataclass
class ValidationReport:
    rows: int
    groups: int
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    class_counts: dict[str, int] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return not self.errors

    def as_dict(self) -> dict:
        return {"rows": self.rows, "groups": self.groups, "ok": self.ok, "errors": self.errors, "warnings": self.warnings, "class_counts": self.class_counts}


def validate(frame: pd.DataFrame, features: list[str]) -> ValidationReport:
    report = ValidationReport(rows=len(frame), groups=frame[GROUP].nunique() if GROUP in frame else 0)
    missing = [column for column in (*features, LABEL, GROUP) if column not in frame]
    if missing:
        report.errors.append(f"Missing columns: {', '.join(missing)}")
        return report
    numeric = frame[features].apply(pd.to_numeric, errors="coerce")
    if (bad := numeric.isna().sum()).any():
        report.errors.append(f"Non-numeric or empty values: {bad[bad > 0].to_dict()}")
    if (negative := (numeric < 0).sum()).any():
        report.errors.append(f"Negative values: {negative[negative > 0].to_dict()}")
    if "uplink_ratio" in numeric and not numeric["uplink_ratio"].between(0, 1).all():
        report.errors.append("uplink_ratio outside [0, 1]")
    if {"bytes_total", "bytes_up", "bytes_down"} <= set(numeric):
        mismatch = (numeric["bytes_up"] + numeric["bytes_down"] - numeric["bytes_total"]).abs() > 1
        if mismatch.any():
            report.warnings.append(f"{int(mismatch.sum())} row(s) where bytes_up + bytes_down != bytes_total")
    unknown = sorted(set(frame[LABEL]) - set(TRAFFIC_CLASSES))
    if unknown:
        report.errors.append(f"Unknown traffic labels: {unknown}")
    report.class_counts = {label: int(count) for label, count in frame[LABEL].value_counts().items()}
    absent = [label for label in TRAFFIC_CLASSES if label not in report.class_counts]
    if absent:
        report.warnings.append(f"Classes with no samples: {absent}")
    if frame.duplicated(subset=features + [LABEL]).any():
        report.warnings.append(f"{int(frame.duplicated(subset=features + [LABEL]).sum())} duplicate feature rows")
    return report


def load_synthetic(path: Path) -> tuple[pd.DataFrame, ValidationReport]:
    """The supplied 2,000-row CSV (synthetic lab ground truth, scaffolding only)."""
    frame = pd.read_csv(path)
    # IPSEC-001-07 -> IPSEC-001: rows sharing a configuration must stay on one side of the split.
    frame[GROUP] = frame["capture_id"].str.rsplit("-", n=1).str[0]
    frame = frame.rename(columns={"traffic_label": LABEL})
    report = validate(frame, BASE_FEATURES)
    if "dataset_origin" in frame and set(frame["dataset_origin"]) != {"synthetic_lab_ground_truth"}:
        report.warnings.append("dataset_origin is not uniformly synthetic_lab_ground_truth")
    return frame, report


def session_features(pcap: Path) -> dict[str, float]:
    """Traffic and ESP-structure features for one session capture (metadata pass only; sessions carry no IKE)."""
    from app.packet.esp_structure import ESP_FEATURES, esp_structure
    from app.packet.traffic import extract_traffic_metadata
    from app.packet.tshark import TSharkService

    packets = TSharkService().packet_records(pcap)
    structure = esp_structure(packets)
    measured = structure["features"]
    cipher = structure.get("cipher") or {}
    return {**from_traffic_metadata(extract_traffic_metadata(packets, [])["features"]),
            **{name: float(measured.get(name, float("nan"))) for name in ESP_FEATURES},
            # Result of the training-free Bayesian cipher inference, kept for measuring its accuracy.
            "esp_cipher_inferred": cipher.get("family") if cipher.get("status") != "ambiguous" else None}


def load_sessions(directory: Path, cache: Path | None = None, workers: int = 6) -> tuple[pd.DataFrame, ValidationReport]:
    """Labelled testbed sessions (pcap + json). Parsed features are cached by pcap hash; new files are parsed in parallel."""
    from concurrent.futures import ThreadPoolExecutor, as_completed

    cached: dict[str, dict] = {}
    if cache and cache.exists():
        previous = pd.read_csv(cache)
        # A cache written before the feature set changed is ignored and rebuilt.
        from app.packet.esp_structure import ESP_FEATURES

        if set(FULL_FEATURES) | set(ESP_FEATURES) | {"esp_cipher_inferred"} <= set(previous.columns):
            cached = {row["sha256"]: row for row in previous.to_dict("records")}
    labelled = []
    for label_path in sorted(directory.glob("*.json")):
        label = json.loads(label_path.read_text(encoding="utf-8"))
        pcap = directory / label["pcap_filename"]
        if pcap.exists():
            labelled.append((label, pcap, hashlib.sha256(pcap.read_bytes()).hexdigest()))

    pending = [(pcap, digest) for _, pcap, digest in labelled if digest not in cached]
    if pending:
        print(f"Extracting traffic features from {len(pending)} new capture(s) with {workers} parallel TShark workers "
              f"({len(labelled) - len(pending)} cached)...", flush=True)
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(session_features, pcap): digest for pcap, digest in pending}
            for done, future in enumerate(as_completed(futures), start=1):
                cached[futures[future]] = {**future.result(), "sha256": futures[future]}
                if done % 10 == 0 or done == len(pending):
                    print(f"  {done}/{len(pending)}", flush=True)

    rows = []
    for label, _, digest in labelled:
        row = dict(cached[digest])
        row.update({"session_id": label["session_id"], LABEL: label["traffic"], GROUP: label["group"], "sha256": digest,
                    "dataset_origin": label.get("dataset_origin", "unknown"),
                    # Ground truth for the protocol-inference models (mode and ESP cipher family).
                    "mode": (label.get("mode") or "").capitalize() or None, "esp_proposal": label.get("esp_proposal"),
                    "ip_version": label.get("ip_version")})
        rows.append(row)
    frame = pd.DataFrame(rows)
    if frame.empty:
        return frame, ValidationReport(0, 0, errors=[f"No labelled sessions found in {directory}"])
    if cache:
        cache.parent.mkdir(parents=True, exist_ok=True)
        frame.to_csv(cache, index=False)
    report = validate(frame, FULL_FEATURES)
    too_small = frame[frame["packet_count"] < 10]
    if len(too_small):
        report.warnings.append(f"{len(too_small)} session(s) have fewer than 10 ESP packets")
    return frame, report


def group_split(frame: pd.DataFrame, seed: int = 26160, fractions: tuple[float, float, float] = (0.70, 0.15, 0.15)) -> dict[str, pd.DataFrame]:
    """Split whole groups (configurations/captures) into train/validation/test; no group spans two splits."""
    groups = np.array(sorted(frame[GROUP].unique()))
    if len(groups) < 3:
        raise ValueError(
            f"Need at least 3 groups for a group-level split, found {len(groups)} ({', '.join(groups)}). "
            "Record more scenarios with `run_testbed.py --dataset` before training on sessions."
        )
    rng = np.random.default_rng(seed)
    rng.shuffle(groups)
    n_test = max(1, round(len(groups) * fractions[2]))
    n_val = max(1, round(len(groups) * fractions[1]))
    test, validation, train = groups[:n_test], groups[n_test:n_test + n_val], groups[n_test + n_val:]
    return {
        "train": frame[frame[GROUP].isin(train)],
        "validation": frame[frame[GROUP].isin(validation)],
        "test": frame[frame[GROUP].isin(test)],
    }
