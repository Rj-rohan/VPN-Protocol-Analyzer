"""Build the released dataset package: labelled captures, derived features, splits, a dataset card and checksums.

    python -m app.dataset_export                     # combined source (lab sessions + ISCX-derived windows)
    python -m app.dataset_export --source sessions   # lab sessions only (no ISCX import needed)
    python -m app.dataset_export --no-pcaps --zip    # features-only package, also zipped
    python -m app.dataset_export --verify data\\release\\<package>

The package contains exactly what the models were trained and evaluated on: the same feature rows,
the same group-level 70/15/15 split and the same 5-fold group cross-validation folds (taken from
app.ml.train, not recomputed differently). ISCX VPN-nonVPN 2016 raw captures are never copied; only
features derived from them are, with the citation the dataset licence requires.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import platform
import re
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

from app.config import REPO_DIR
from app.ml.preprocessing import GROUP, LABEL
from app.ml.train import MODELS_DIR, SESSIONS_DIR, group_folds, load_frame, split_per_source

TESTBED_DIR = REPO_DIR / "data" / "raw" / "testbed"
EVALUATION_DIR = REPO_DIR / "data" / "processed" / "evaluation"
CARD_TEMPLATE = REPO_DIR / "docs" / "dataset.md"
DEFAULT_OUTPUT = REPO_DIR / "data" / "release"
CHECKSUMS = "SHA256SUMS"
ISCX_ORIGINS = {"iscx_vpn_2016_openvpn_converted", "iscx_nonvpn_2016_esp_converted"}
LABEL_COLUMNS = [LABEL, GROUP, "session_id", "dataset_origin", "mode", "esp_proposal", "ip_version", "source_file"]
ISCX_CITATION = ('G. Draper-Gil, A. H. Lashkari, M. S. I. Mamun, A. A. Ghorbani, "Characterization of Encrypted and VPN Traffic '
                 'Using Time-Related Features", Proc. ICISSP 2016, pp. 407-414. https://www.unb.ca/cic/datasets/vpn.html')

# Feature dictionary: exact names first, then prefixes. Units are in the names (_bytes, _ms, _seconds).
_EXACT = {
    "duration_seconds": "Time from the first to the last ESP/AH packet of the flow",
    "packet_count": "ESP/AH packets in the flow",
    "uplink_ratio": "Share of bytes sent by the client (initiator) side",
    "direction_changes": "Number of times consecutive packets switch direction",
    "direction_change_rate": "direction_changes / packet_count",
    "burst_count": "Runs of packets separated by at most 5 ms",
    "idle_fraction": "Share of the duration spent in gaps longer than 1 s",
    "idle_periods": "Number of gaps longer than 1 s",
    "max_idle_seconds": "Longest gap between packets",
    "small_packet_up_fraction": "Share of uplink packets of at most 150 bytes (ESP-wrapped ACKs and control)",
    "large_packet_down_fraction": "Share of downlink packets of at least 1200 bytes (near-MTU data)",
    "bytes_per_second_cv": "Coefficient of variation of per-second byte counts (steady vs bursty)",
    "active_second_fraction": "Share of one-second slots that carry any packet",
    "peak_to_mean_bytes_ratio": "Busiest second divided by the mean second",
    "esp_measured_packets": "ESP packets whose payload length could be measured",
    "esp_distinct_lengths": "Distinct ESP payload lengths (the Bayesian cipher inference needs at least 4)",
    "esp_inner_upper_min": "Upper bound of the smallest inner packet after removing the inferred IV/ICV/trailer",
    "esp_layout_decided": "1 if the Bayesian length-lattice inference chose a cipher layout, else 0",
    "esp_outer_ipv6": "1 if the outer header is IPv6",
    "esp_udp_encapsulated": "1 if ESP is UDP-encapsulated (NAT-T)",
    "esp_readable_fraction": "Share of ESP packets that decode as ESP-NULL (cleartext payload)",
    "esp_cipher_inferred": "Cipher family chosen by the training-free Bayesian inference (empty if undecided)",
    "esp_frac_inner_ack_transport": "Share of inner sizes 14-36 bytes: a TCP ACK with no inner IP header (transport mode)",
    "esp_frac_inner_ack_tunnel": "Share of inner sizes 36-58 bytes: a TCP ACK plus an inner IPv4 header (tunnel mode)",
    "esp_frac_inner_ack_tunnel_v6": "Share of inner sizes 56-78 bytes: a TCP ACK plus an inner IPv6 header",
    "traffic_label": "Ground-truth traffic class: " + ", ".join(("Web", "Video", "VoIP", "Email", "Chat", "ICMP", "File-Transfer")),
    "group": "Recording group (VPN configuration or source capture); no group spans two splits or folds",
    "session_id": "Unique row identifier",
    "dataset_origin": "Data source of the row",
    "mode": "Ground-truth IPsec mode (lab sessions only)",
    "esp_proposal": "Ground-truth strongSwan/XFRM ESP proposal (lab sessions only)",
    "ip_version": "Ground-truth outer IP version (lab sessions only)",
    "source_file": "ISCX capture file the window was cut from",
    "sha256": "SHA-256 of the session pcap in captures/sessions/",
    "split": "Group-level hold-out split used for model selection reporting: train, validation or test",
    "cv_fold": "Fold (0-4) in which the row's group is held out during 5-fold group cross-validation",
}
for _unit in ("packets", "bytes"):
    _EXACT |= {f"{_unit}_up": f"{_unit.capitalize()} sent by the client side", f"{_unit}_down": f"{_unit.capitalize()} sent to the client side",
               f"{_unit}_per_second": f"{_unit.capitalize()} per second, both directions",
               f"{_unit}_per_second_up": f"{_unit.capitalize()} per second from the client side",
               f"{_unit}_per_second_down": f"{_unit.capitalize()} per second to the client side"}
_EXACT["bytes_total"] = "Bytes in both directions (outer ESP/AH packet lengths)"
_STAT = {"avg": "Mean", "std": "Standard deviation of", "min": "Smallest", "max": "Largest"}
_QUANTITY = {"packet_size": "packet size", "interarrival": "inter-arrival time", "burst_packets": "packets per burst",
             "burst": "burst size", "inter_burst_gap": "gap between consecutive bursts"}
_STATISTIC = re.compile(r"(avg|std|min|max|p\d\d)_(.+?)(?:_(up|down))?(?:_(bytes|ms))?")


def describe(column: str) -> str:
    if column in _EXACT:
        return _EXACT[column]
    if column.startswith("size_bin_"):
        return "Share of packets in size bin " + column[9] + " of [0,128), [128,256), [256,512), [512,1024), [1024,1400), [1400,inf) bytes"
    if column.startswith("esp_frac_inner_le_"):
        return f"Share of ESP packets whose inner (decapsulated) size is at most {column.rsplit('_', 1)[1]} bytes"
    if column.startswith("esp_inner_"):
        stat = column.removeprefix("esp_inner_")
        return f"{'Minimum' if stat == 'min' else str(int(stat[1:])) + 'th percentile of'} inner packet size after removing the inferred ESP overhead (bytes)"
    match = _STATISTIC.fullmatch(column)
    if match and match[2] in _QUANTITY:
        stat, quantity, direction, unit = match.groups()
        stat = _STAT.get(stat) or f"{int(stat[1:])}th percentile of"
        return (f"{stat} {_QUANTITY[quantity]}" + {"up": ", client to server", "down": ", server to client"}.get(direction or "", "")
                + (f" ({unit})" if unit else ""))
    return ""


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def assign_splits(frame: pd.DataFrame) -> pd.DataFrame:
    """Add the exact split and cross-validation fold app.ml.train uses for every row."""
    frame = frame.copy()
    for name, part in split_per_source(frame).items():
        frame.loc[part.index, "split"] = name
    for fold, (_, test_positions) in enumerate(group_folds(frame)):
        frame.loc[frame.index[test_positions], "cv_fold"] = fold
    frame["cv_fold"] = frame["cv_fold"].astype(int)
    return frame


def _copy_labelled(source: Path, target: Path, pattern: str, include_pcaps: bool) -> int:
    """Copy pcap + json ground-truth pairs. Returns the number of pairs."""
    target.mkdir(parents=True, exist_ok=True)
    pairs = 0
    for label_path in sorted(source.glob(pattern)):
        label = json.loads(label_path.read_text(encoding="utf-8"))
        pcap = source / label["pcap_filename"]
        if not pcap.exists():
            continue
        shutil.copy2(label_path, target / label_path.name)
        if include_pcaps:
            shutil.copy2(pcap, target / pcap.name)
        pairs += 1
    return pairs


def _write_csv(frame: pd.DataFrame, path: Path, features: list[str]) -> None:
    labels = [c for c in LABEL_COLUMNS if c in frame]
    extra = [c for c in frame.columns if c not in labels and c not in features and c not in ("split", "cv_fold")]
    frame[labels + ["split", "cv_fold"] + features + extra].to_csv(path, index=False)


def _stats(frame: pd.DataFrame) -> dict:
    return {
        "rows": int(len(frame)),
        "groups": int(frame[GROUP].nunique()),
        "by_class": {k: int(v) for k, v in frame[LABEL].value_counts().sort_index().items()},
        "by_split": {k: int(v) for k, v in frame["split"].value_counts().items()},
    }


def _card(manifest: dict) -> str:
    template = CARD_TEMPLATE.read_text(encoding="utf-8") if CARD_TEMPLATE.exists() else "# IPsec traffic dataset\n"
    lines = [template.rstrip(), "", "---", "", f"## This package: {manifest['name']}", "",
             f"Built {manifest['created_at']} from source `{manifest['source']}`; pcaps included: {manifest['includes_pcaps']}.", "",
             "| Part | Rows | Groups | Classes |", "|---|---|---|---|"]
    for name, part in manifest["feature_tables"].items():
        classes = ", ".join(f"{k} {v}" for k, v in part["by_class"].items())
        lines.append(f"| `features/{name}` | {part['rows']} | {part['groups']} | {classes} |")
    lines += ["", f"Labelled captures: {manifest['captures']['testbed']} strongSwan testbed captures, "
                  f"{manifest['captures']['sessions']} lab sessions.", "",
              f"Verify the files with `sha256sum -c {CHECKSUMS}` (Linux/macOS) or "
              f"`python -m app.dataset_export --verify <this folder>` from the project's backend.", ""]
    return "\n".join(lines)


def build(source: str, output: Path, version: str, include_pcaps: bool, make_zip: bool) -> Path:
    frame, features = load_frame(source)
    frame = assign_splits(frame)
    name = f"ipsec-sih26160-dataset-{version}"
    root = output / name
    if root.exists():
        shutil.rmtree(root)
    (root / "features").mkdir(parents=True)

    lab = frame[~frame["dataset_origin"].isin(ISCX_ORIGINS)]
    iscx = frame[frame["dataset_origin"].isin(ISCX_ORIGINS)]
    tables = {}
    if len(lab):
        _write_csv(lab.dropna(axis=1, how="all"), root / "features" / "lab_sessions.csv", features)
        tables["lab_sessions.csv"] = _stats(lab)
    if len(iscx):
        # Derived features only: the ISCX raw captures are not redistributed.
        _write_csv(iscx.dropna(axis=1, how="all"), root / "features" / "iscx_windows.csv", features)
        tables["iscx_windows.csv"] = _stats(iscx)

    groups = (frame.groupby(GROUP)
              .agg(dataset_origin=("dataset_origin", "first"), rows=(LABEL, "size"), split=("split", "first"),
                   cv_fold=("cv_fold", "first"), classes=(LABEL, lambda s: ";".join(sorted(set(s)))))
              .reset_index())
    (root / "splits").mkdir()
    groups.to_csv(root / "splits" / "groups.csv", index=False)

    columns = sorted(set().union(*(pd.read_csv(root / "features" / t, nrows=0).columns for t in tables)))
    with (root / "features" / "feature_dictionary.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["column", "role", "description"])
        for column in columns:
            role = "feature" if column in features else "split" if column in ("split", "cv_fold") else "label/metadata"
            writer.writerow([column, role, describe(column)])

    captures = {"testbed": _copy_labelled(TESTBED_DIR, root / "captures" / "testbed", "capture_*.json", include_pcaps),
                "sessions": _copy_labelled(SESSIONS_DIR, root / "captures" / "sessions", "*.json", include_pcaps)}
    if (TESTBED_DIR / "manifest.csv").exists():
        shutil.copy2(TESTBED_DIR / "manifest.csv", root / "captures" / "testbed" / "manifest.csv")

    (root / "results").mkdir()
    for path in [*EVALUATION_DIR.glob("evaluation_report.*"), *MODELS_DIR.glob("*_metrics.json"), *MODELS_DIR.glob("*_report.md")]:
        shutil.copy2(path, root / "results" / path.name)

    manifest = {
        "name": name, "version": version, "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source": source, "includes_pcaps": include_pcaps, "features": features,
        "feature_tables": tables, "captures": captures,
        "split_method": "group-level 70/15/15 within each data source (seed 26160); 5-fold StratifiedGroupKFold (seed 26160)",
        "origins": {k: int(v) for k, v in frame["dataset_origin"].value_counts().items()},
        "not_included": ["ISCX VPN-nonVPN 2016 raw captures (obtain from the Canadian Institute for Cybersecurity)",
                         "synthetic problem-statement CSV", "trained model binaries"],
        "citation_required": ISCX_CITATION if len(iscx) else None,
        "generator": {"script": "backend/app/dataset_export.py", "python": platform.python_version(), "pandas": pd.__version__},
    }
    (root / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    (root / "README.md").write_text(_card(manifest), encoding="utf-8")

    files = sorted(p for p in root.rglob("*") if p.is_file() and p.name != CHECKSUMS)
    (root / CHECKSUMS).write_text("".join(f"{sha256(p)}  {p.relative_to(root).as_posix()}\n" for p in files), encoding="utf-8")
    if make_zip:
        archive = shutil.make_archive(str(root), "zip", root_dir=output, base_dir=name)
        print(f"Zipped: {archive}")
    return root


def verify(root: Path) -> list[str]:
    """Paths whose checksum does not match, plus any file missing from the package."""
    problems = []
    for line in (root / CHECKSUMS).read_text(encoding="utf-8").splitlines():
        expected, relative = line.split("  ", 1)
        path = root / relative
        if not path.exists():
            problems.append(f"missing: {relative}")
        elif sha256(path) != expected:
            problems.append(f"checksum mismatch: {relative}")
    return problems


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source", choices=("combined", "sessions", "iscx"), default="combined")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--version", default=datetime.now(timezone.utc).strftime("%Y.%m.%d"))
    parser.add_argument("--no-pcaps", action="store_true", help="features, labels and splits only")
    parser.add_argument("--zip", action="store_true", help="also write <package>.zip")
    parser.add_argument("--verify", type=Path, metavar="PACKAGE_DIR", help="check a package against its SHA256SUMS and exit")
    args = parser.parse_args()
    if args.verify:
        problems = verify(args.verify)
        print("\n".join(problems) if problems else f"OK: every file in {args.verify} matches {CHECKSUMS}")
        sys.exit(1 if problems else 0)
    root = build(args.source, args.output, args.version, not args.no_pcaps, args.zip)
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    print(f"Dataset package written to {root}")
    for table, info in manifest["feature_tables"].items():
        print(f"  features/{table}: {info['rows']} rows, {info['groups']} groups, splits {info['by_split']}")
    print(f"  captures: {manifest['captures']['testbed']} testbed + {manifest['captures']['sessions']} sessions"
          f"{'' if manifest['includes_pcaps'] else ' (labels only, --no-pcaps)'}")


if __name__ == "__main__":
    main()
