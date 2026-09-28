"""Train the encrypted-traffic classifier.

    python -m app.ml.train --source synthetic   # supplied CSV (scaffolding)
    python -m app.ml.train --source sessions    # lab ESP sessions (strongSwan + Linux XFRM)
    python -m app.ml.train --source iscx        # ISCX VPN-nonVPN 2016 real-app windows only
    python -m app.ml.train --source combined    # lab sessions + ISCX, split within each source
    python -m app.ml.train                      # sessions if available, else synthetic

Every trained model is also archived in data/models/versions/<version>/.

RandomForest and XGBoost are trained on the same group-level split; the one
with the better validation macro-F1 is saved together with its held-out test
metrics. Nothing is reported as accurate unless it was measured on test groups
never seen during training.
"""
from __future__ import annotations

import argparse
import json
import statistics
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, precision_recall_fscore_support
from sklearn.model_selection import StratifiedGroupKFold, StratifiedKFold
from sklearn.preprocessing import LabelEncoder
from sklearn.utils.class_weight import compute_sample_weight
from xgboost import XGBClassifier

from app.config import REPO_DIR
from app.ml.features import BASE_FEATURES, FULL_FEATURES, TRAFFIC_CLASSES
from app.ml.preprocessing import GROUP, LABEL, group_split, load_sessions, load_synthetic, validate

DATA_DIR = REPO_DIR / "data"
SYNTHETIC_CSV = DATA_DIR / "ipsec_sih_26160_dataset_2000.csv"
SESSIONS_DIR = DATA_DIR / "raw" / "traffic_sessions"
ISCX_CSV = DATA_DIR / "processed" / "iscx_features.csv"
MODELS_DIR = DATA_DIR / "models"
SEED = 26160
CV_REPEATS = 5  # different random group splits averaged for the reported accuracy
EXTERNAL_TEST_ORIGINS = {"real_app_phone_ikev2"}  # real recordings used only to test the traffic classifier


def _candidates() -> dict:
    return {
        "RandomForest": lambda: RandomForestClassifier(n_estimators=300, min_samples_leaf=2, class_weight="balanced", random_state=SEED, n_jobs=-1),
        "XGBoost": lambda: XGBClassifier(n_estimators=300, max_depth=4, learning_rate=0.08, subsample=0.9, colsample_bytree=0.9,
                                         eval_metric="mlogloss", random_state=SEED, n_jobs=4),
    }


def fit(model, frame: pd.DataFrame, features: list[str], encoder: LabelEncoder):
    target = encoder.transform(frame[LABEL])
    if isinstance(model, XGBClassifier):
        # Balance classes the way RandomForest's class_weight="balanced" does.
        model.fit(frame[features], target, sample_weight=compute_sample_weight("balanced", target))
    else:
        model.fit(frame[features], target)
    return model


def evaluate(model, encoder: LabelEncoder, frame: pd.DataFrame, features: list[str]) -> dict:
    if frame.empty:
        return {"samples": 0}
    return scores(frame, encoder.inverse_transform(model.predict(frame[features])))


def group_folds(frame: pd.DataFrame, folds: int = 5, seed: int = SEED) -> list[tuple[np.ndarray, np.ndarray]]:
    """The (train, test) row positions of the group cross-validation; the SEED split is exported with the dataset package."""
    splitter = StratifiedGroupKFold(n_splits=min(folds, frame[GROUP].nunique()), shuffle=True, random_state=seed)
    return list(splitter.split(frame, frame[LABEL], frame[GROUP]))


def out_of_fold(frame: pd.DataFrame, fit_predict, folds: int = 5, seed: int = SEED) -> pd.Series:
    """Predictions for every row from a model that never saw the row's group."""
    predicted = pd.Series(index=frame.index, dtype=object)
    for train_index, test_index in group_folds(frame, folds, seed):
        predicted.iloc[test_index] = fit_predict(frame.iloc[train_index], frame.iloc[test_index])
    return predicted


def spread(values: list[float]) -> dict:
    return {"mean": round(statistics.mean(values), 4), "sd": round(statistics.stdev(values), 4) if len(values) > 1 else 0.0,
            "min": round(min(values), 4), "max": round(max(values), 4), "splits": len(values)}


def cross_validate(frame: pd.DataFrame, features: list[str], build, encoder: LabelEncoder, folds: int = 5,
                   repeats: int = CV_REPEATS) -> dict:
    """Group cross-validation repeated over `repeats` different random splits.

    With only a few recordings per class (e.g. two e-mail captures), which recordings land in the same test fold
    moves accuracy by several points, so the headline figure is the mean over splits, reported with its spread.
    Detailed per-class metrics and the confusion matrix come from the first (SEED) split."""
    def fit_predict(train_part: pd.DataFrame, test_part: pd.DataFrame):
        return encoder.inverse_transform(fit(build(), train_part, features, encoder).predict(test_part[features]))

    runs = [out_of_fold(frame, fit_predict, folds, SEED + offset) for offset in range(repeats)]
    correct = [run == frame[LABEL] for run in runs]
    first = runs[0]
    return {
        "folds": min(folds, frame[GROUP].nunique()),
        "overall": scores(frame, first.to_numpy()),
        "by_source": {origin: scores(part, first.loc[part.index].to_numpy()) for origin, part in frame.groupby("dataset_origin")},
        "repeated": {
            "accuracy": spread([float(c.mean()) for c in correct]),
            "macro_f1": spread([scores(frame, run.to_numpy())["macro_f1"] for run in runs]),
            "by_source": {origin: spread([float(c.loc[part.index].mean()) for c in correct])
                          for origin, part in frame.groupby("dataset_origin")},
        },
    }


def random_split_accuracy(frame: pd.DataFrame, features: list[str], build, encoder: LabelEncoder, folds: int = 5) -> dict:
    """Window-level random split (windows of one recording on both sides). Only for comparison with
    studies that evaluate this way; it overstates accuracy on unseen recordings."""
    predicted = pd.Series(index=frame.index, dtype=object)
    for train_index, test_index in StratifiedKFold(n_splits=folds, shuffle=True, random_state=SEED).split(frame, frame[LABEL]):
        model = fit(build(), frame.iloc[train_index], features, encoder)
        predicted.iloc[test_index] = encoder.inverse_transform(model.predict(frame.iloc[test_index][features]))
    return {origin: float((predicted.loc[part.index] == part[LABEL]).mean()) for origin, part in frame.groupby("dataset_origin")}


def scores(frame: pd.DataFrame, predicted, classes: tuple[str, ...] = TRAFFIC_CLASSES) -> dict:
    truth = frame[LABEL].to_numpy()
    labels = [label for label in classes if label in set(truth) | set(predicted)]
    precision, recall, f1, support = precision_recall_fscore_support(truth, predicted, labels=labels, zero_division=0)
    macro = precision_recall_fscore_support(truth, predicted, labels=labels, average="macro", zero_division=0)
    return {
        "samples": int(len(frame)),
        "groups": sorted(frame[GROUP].unique().tolist()),
        "accuracy": float(accuracy_score(truth, predicted)),
        "macro_precision": float(macro[0]),
        "macro_recall": float(macro[1]),
        "macro_f1": float(macro[2]),
        "per_class": {label: {"precision": float(p), "recall": float(r), "f1": float(f), "support": int(s)}
                      for label, p, r, f, s in zip(labels, precision, recall, f1, support)},
        "confusion_matrix": {"labels": labels, "matrix": confusion_matrix(truth, predicted, labels=labels).tolist()},
    }


def load_iscx(path: Path | None = None) -> pd.DataFrame:
    path = path or ISCX_CSV
    if not path.exists():
        raise SystemExit(f"{path} not found. Run `python -m app.ml.iscx` after extracting the ISCX VPN captures.")
    frame = pd.read_csv(path)
    missing = [f for f in FULL_FEATURES if f not in frame]
    if missing:
        raise SystemExit(f"{path.name} was built with an older feature set (missing {len(missing)} features). Re-run `python -m app.ml.iscx`.")
    return frame


def split_per_source(frame: pd.DataFrame) -> dict[str, pd.DataFrame]:
    """Group-level split done separately inside each data source, so every split contains every source."""
    parts: dict[str, list[pd.DataFrame]] = {"train": [], "validation": [], "test": []}
    for origin, subset in frame.groupby("dataset_origin"):
        if subset[GROUP].nunique() >= 3:
            for name, part in group_split(subset, seed=SEED).items():
                parts[name].append(part)
        else:
            print(f"Note: {origin} has fewer than 3 groups; all of it is used for training.")
            parts["train"].append(subset)
    return {name: pd.concat(chunks) if chunks else frame.iloc[0:0] for name, chunks in parts.items()}


def resolve_source(source: str) -> str:
    if source == "auto":
        return "sessions" if SESSIONS_DIR.exists() and any(SESSIONS_DIR.glob("*.json")) else "synthetic"
    return source


def load_frame(source: str) -> tuple[pd.DataFrame, list[str]]:
    """The validated training frame and feature list for a --source (also used by the dataset package)."""
    if source == "synthetic":
        frame, report = load_synthetic(SYNTHETIC_CSV)
        features = BASE_FEATURES
    else:
        features = FULL_FEATURES
        frames = []
        if source in ("sessions", "combined"):
            sessions, report = load_sessions(SESSIONS_DIR, cache=DATA_DIR / "processed" / "traffic_sessions_features.csv")
            if not report.ok:
                raise SystemExit(f"Session dataset validation failed: {report.errors}")
            frames.append(sessions)
        if source in ("iscx", "combined"):
            frames.append(load_iscx())
        frame = pd.concat(frames, ignore_index=True)
        report = validate(frame, features)
    if not report.ok:
        raise SystemExit(f"Dataset validation failed: {report.errors}")
    if "dataset_origin" not in frame:
        frame["dataset_origin"] = "synthetic_lab_ground_truth"
    frame.attrs["validation"] = report.as_dict()
    return frame, features


def external_test(model, encoder: LabelEncoder, frame: pd.DataFrame, features: list[str]) -> dict:
    """Accuracy on recordings kept out of training: per window, and per recording by majority vote of its windows."""
    if frame.empty:
        return {}
    predicted = pd.Series(encoder.inverse_transform(model.predict(frame[features])), index=frame.index)
    recordings = []
    for group, part in frame.groupby(GROUP):
        vote = predicted.loc[part.index].value_counts().idxmax()
        recordings.append({"recording": group, "truth": part[LABEL].iloc[0], "predicted": vote,
                           "windows": int(len(part)), "windows_correct": int((predicted.loc[part.index] == part[LABEL]).sum())})
    return {"windows": scores(frame, predicted.to_numpy()),
            "recordings": recordings,
            "recording_accuracy": float(sum(r["truth"] == r["predicted"] for r in recordings) / len(recordings))}


def train(source: str) -> dict:
    source = resolve_source(source)
    frame, features = load_frame(source)
    # Real phone recordings are an independent test set, not training data: their class semantics differ from the
    # ISCX training data (a WhatsApp video call is two-way and steady, ISCX "Video" is one-way streaming), and adding
    # them lowered real-app accuracy from 79.1% to 74.1-74.4% (mean over 8 group splits). Kept out, they measure how
    # the model does on real traffic it has never seen.
    validation = frame.attrs["validation"]
    held_out = frame[frame["dataset_origin"].isin(EXTERNAL_TEST_ORIGINS)]
    frame = frame[~frame["dataset_origin"].isin(EXTERNAL_TEST_ORIGINS)].reset_index(drop=True)
    frame.attrs["validation"] = validation
    origin = "+".join(sorted(set(frame["dataset_origin"])))

    splits = split_per_source(frame)
    encoder = LabelEncoder().fit(list(TRAFFIC_CLASSES))
    results = {}
    for name, build in _candidates().items():
        print(f"Training {name}: 5-fold group cross-validation over {CV_REPEATS} splits, then the hold-out split...", flush=True)
        model = fit(build(), splits["train"], features, encoder)
        results[name] = {
            "model": model,
            "cross_validation": cross_validate(frame, features, build, encoder),
            "validation": evaluate(model, encoder, splits["validation"], features),
            "test": evaluate(model, encoder, splits["test"], features),
            # Held-out accuracy for each data source separately (e.g. lab sessions vs ISCX).
            "test_by_source": {origin: evaluate(model, encoder, part, features)
                               for origin, part in splits["test"].groupby("dataset_origin")},
        }
    # Repeated cross-validation holds out every group once per split, so it is a steadier basis for choosing
    # than one validation split (or one cross-validation split).
    best = max(results, key=lambda name: results[name]["cross_validation"]["repeated"]["macro_f1"]["mean"])
    results[best]["random_split_accuracy"] = random_split_accuracy(frame, features, _candidates()[best], encoder)
    importances = dict(sorted(zip(features, map(float, getattr(results[best]["model"], "feature_importances_", np.zeros(len(features))))),
                              key=lambda item: -item[1])[:10])

    trained_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    metrics = {
        "trained_at": trained_at,
        "training_source": origin,
        "dataset_validation": frame.attrs["validation"],
        "split": {name: {"rows": int(len(part)), "groups": int(part[GROUP].nunique()),
                         "by_source": {o: int(n) for o, n in part["dataset_origin"].value_counts().items()}}
                  for name, part in splits.items()},
        "split_method": "group-level (configuration/session/capture group), 70/15/15 within each data source, no group shared between splits",
        "features": features,
        "selected_model": best,
        "selection_criterion": f"5-fold group cross-validation macro-F1, mean over {CV_REPEATS} splits",
        "models": {name: {"cross_validation": r["cross_validation"], "validation": r["validation"], "test": r["test"],
                          "test_by_source": r["test_by_source"], "random_split_accuracy": r.get("random_split_accuracy")}
                   for name, r in results.items()},
        "top_feature_importances": importances,
        # Real recordings never used for training (e.g. WhatsApp and Gmail through a phone's IKEv2 VPN).
        "external_test": external_test(results[best]["model"], encoder, held_out, features),
    }
    suffix ={"synthetic": "synthetic", "sessions": "testbed", "iscx": "iscx", "combined": "combined"}[source]
    version = f"{suffix}-{trained_at[:19].replace(':', '').replace('-', '')}"
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    artifact = {
        "model": results[best]["model"], "encoder": encoder, "model_name": best, "features": features,
        "version": version, "training_source": origin, "trained_at": trained_at,
        "test_metrics": {k: results[best]["test"].get(k) for k in ("accuracy", "macro_f1", "samples")},
        # Cross-validated accuracy, mean over several group splits: the figure used for the AI confidence score.
        "cv_accuracy": results[best]["cross_validation"]["repeated"]["accuracy"]["mean"],
        "cv_accuracy_sd": results[best]["cross_validation"]["repeated"]["accuracy"]["sd"],
        "cv_accuracy_by_source": {o: r["mean"] for o, r in results[best]["cross_validation"]["repeated"]["by_source"].items()},
    }
    # Every model is archived under versions/ so a retrain never loses an earlier model.
    archive = MODELS_DIR / "versions" / version
    archive.mkdir(parents=True, exist_ok=True)
    for directory in (MODELS_DIR, archive):
        joblib.dump(artifact, directory / f"traffic_classifier_{suffix}.joblib")
        (directory / f"traffic_classifier_{suffix}_metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
        (directory / f"traffic_classifier_{suffix}_report.md").write_text(markdown_report(metrics), encoding="utf-8")
    return metrics


def markdown_report(metrics: dict) -> str:
    lines = [
        f"# Traffic classifier ({metrics['training_source']})", "",
        f"Trained {metrics['trained_at']}. Split: {metrics['split_method']}.", "",
        "| Split | Rows | Groups |", "|---|---|---|",
        *(f"| {name} | {info['rows']} | {info['groups']} |" for name, info in metrics["split"].items()), "",
        "| Model | Val accuracy | Val macro-F1 | Test accuracy | Test macro-F1 |", "|---|---|---|---|---|",
    ]
    for name, result in metrics["models"].items():
        v, t = result["validation"], result["test"]
        lines.append(f"| {name}{' (selected)' if name == metrics['selected_model'] else ''} | {v.get('accuracy', 0):.3f} | {v.get('macro_f1', 0):.3f} | {t.get('accuracy', 0):.3f} | {t.get('macro_f1', 0):.3f} |")
    cv = metrics["models"][metrics["selected_model"]].get("cross_validation")
    if cv:
        repeated = cv["repeated"]
        n = repeated["accuracy"]["splits"]
        cell = lambda s: f"**{s['mean']:.1%}** ± {s['sd']:.1%} ({s['min']:.1%}–{s['max']:.1%})"
        lines += ["", f"{cv['folds']}-fold group cross-validation of the selected model, repeated over {n} different random "
                      "group splits (every capture/configuration is held out once per split). Accuracy is the mean ± standard "
                      "deviation over splits, with the worst and best split:", "",
                  "| Source | Rows | Accuracy |", "|---|---|---|",
                  *(f"| {o} | {cv['by_source'][o]['samples']} | {cell(s)} |" for o, s in repeated["by_source"].items()),
                  f"| **all** | {cv['overall']['samples']} | {cell(repeated['accuracy'])} |",
                  "", f"Macro-F1 (all sources): {repeated['macro_f1']['mean']:.3f} ± {repeated['macro_f1']['sd']:.3f}.",
                  "", "With few recordings per class (e.g. two e-mail captures), the split alone moves accuracy by several "
                      "points, so the mean is the figure to quote, not any single split.",
                  "", "Per-class recall (first split): " + ", ".join(f"{k} {v['recall']:.2f}" for k, v in cv["overall"]["per_class"].items())]
        matrix = cv["overall"]["confusion_matrix"]
        lines += ["", "Cross-validation confusion matrix, first split (rows = truth, columns = predicted):", "",
                  "| | " + " | ".join(matrix["labels"]) + " |", "|---" * (len(matrix["labels"]) + 1) + "|",
                  *(f"| {label} | " + " | ".join(map(str, row)) + " |" for label, row in zip(matrix["labels"], matrix["matrix"]))]
    external = metrics.get("external_test") or {}
    if external:
        lines += ["", "Independent real-world test (real apps recorded through a phone's IKEv2 VPN, never used for training): "
                      f"{external['recording_accuracy']:.0%} of recordings by majority vote of their 15 s windows, "
                      f"{external['windows']['accuracy']:.0%} of individual windows.", "",
                  "| Recording | Truth | Predicted (vote) | Windows correct |", "|---|---|---|---|",
                  *(f"| {r['recording']} | {r['truth']} | {r['predicted']} | {r['windows_correct']}/{r['windows']} |"
                    for r in external["recordings"])]
    by_source = metrics["models"][metrics["selected_model"]].get("test_by_source", {})
    if len(by_source) > 1:
        lines += ["", "Held-out test accuracy of the selected model by data source:", "",
                  "| Source | Test rows | Accuracy | Macro-F1 |", "|---|---|---|---|",
                  *(f"| {o} | {r.get('samples', 0)} | {r.get('accuracy', 0):.3f} | {r.get('macro_f1', 0):.3f} |" for o, r in by_source.items())]
    test = metrics["models"][metrics["selected_model"]]["test"]
    matrix = test.get("confusion_matrix", {})
    if matrix:
        labels = matrix["labels"]
        lines += ["", "Test confusion matrix (rows = truth, columns = predicted):", "",
                  "| | " + " | ".join(labels) + " |", "|---" * (len(labels) + 1) + "|",
                  *(f"| {label} | " + " | ".join(map(str, row)) + " |" for label, row in zip(labels, matrix["matrix"]))]
    if metrics["training_source"].startswith("synthetic"):
        lines += ["", "> These scores come from synthetic lab statistics. They say nothing about accuracy on real captures; "
                      "see the testbed evaluation for that."]
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source", choices=("auto", "synthetic", "sessions", "iscx", "combined"), default="auto")
    args = parser.parse_args()
    metrics = train(args.source)
    selected = metrics["models"][metrics["selected_model"]]
    print(f"\nSource: {metrics['training_source']}  selected: {metrics['selected_model']}")
    for name, result in metrics["models"].items():
        repeated = result["cross_validation"]["repeated"]
        print(f"  {name:12} CV acc {repeated['accuracy']['mean']:.3f} ± {repeated['accuracy']['sd']:.3f}  "
              f"CV macro-F1 {repeated['macro_f1']['mean']:.3f} ± {repeated['macro_f1']['sd']:.3f}   "
              f"hold-out test acc {result['test'].get('accuracy', 0):.3f}")
    print(f"Selected model, cross-validation by source (mean ± sd over {CV_REPEATS} group splits; recall from the first split):")
    for origin, result in selected["cross_validation"]["by_source"].items():
        s = selected["cross_validation"]["repeated"]["by_source"][origin]
        recall = ", ".join(f"{k} {v['recall']:.2f}" for k, v in result["per_class"].items() if v["support"])
        print(f"  {origin}: accuracy {s['mean']:.3f} ± {s['sd']:.3f} (range {s['min']:.3f}-{s['max']:.3f}) "
              f"on {result['samples']} rows  (recall: {recall})")
    print(f"Hold-out test accuracy {selected['test'].get('accuracy', 0):.3f} on {selected['test'].get('samples')} rows. Full report in data/models/.")
    external = metrics.get("external_test") or {}
    if external:
        print(f"Independent real-world test (never trained on): {external['recording_accuracy']:.0%} of "
              f"{len(external['recordings'])} recordings by window vote, {external['windows']['accuracy']:.0%} of windows")
        for r in external["recordings"]:
            print(f"   {'OK  ' if r['truth'] == r['predicted'] else 'MISS'} {r['recording']}: {r['truth']} -> {r['predicted']} "
                  f"({r['windows_correct']}/{r['windows']} windows)")
    leaky = selected.get("random_split_accuracy") or {}
    if leaky:
        print("For comparison only, random window-level split (leaky, how many papers report): "
              + ", ".join(f"{o} {a:.3f}" for o, a in leaky.items()))


if __name__ == "__main__":
    main()
