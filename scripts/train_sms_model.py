"""Train TrustLens' local SMS/scam classifier from merged data sources.

Data sources merged:
  1. data/sms_spam_train.csv       — UCI SMS Spam Collection (English, 5574 rows)
  2. data/india_scam_synthetic.csv — Synthetic India-first scam/ham data

The final pipeline uses character n-gram TF-IDF + Logistic Regression.
The model is a SECONDARY signal in TrustLens and does not change the
evidence-weighted risk score produced by the rule engine.
"""
from __future__ import annotations

import csv
import json
from datetime import UTC, datetime
from pathlib import Path

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    precision_recall_fscore_support,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline, FeatureUnion
from sklearn.feature_extraction.text import TfidfVectorizer as TV

ROOT = Path(__file__).resolve().parents[1]
DATASETS = [
    ROOT / "data" / "sms_spam_train.csv",          # UCI English SMS Spam
    ROOT / "data" / "india_scam_synthetic.csv",     # India-first synthetic data
]
MODEL_DIRECTORY = ROOT / "models"
MODEL_PATH = MODEL_DIRECTORY / "sms_spam_model.joblib"
INFO_PATH = MODEL_DIRECTORY / "sms_spam_model_info.json"


def load_rows(path: Path) -> tuple[list[str], list[int]]:
    with path.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    return [row["sms"] for row in rows], [int(row["label"]) for row in rows]


def main() -> None:
    all_texts: list[str] = []
    all_labels: list[int] = []
    source_counts: dict[str, int] = {}

    for ds_path in DATASETS:
        if not ds_path.exists():
            print(f"  [skip] {ds_path.name} not found")
            continue
        texts, labels = load_rows(ds_path)
        print(f"  [load] {ds_path.name}: {len(texts)} rows  (spam={sum(labels)}, ham={len(labels)-sum(labels)})")
        all_texts.extend(texts)
        all_labels.extend(labels)
        source_counts[ds_path.name] = len(texts)

    total = len(all_texts)
    spam_total = sum(all_labels)
    print(f"\nMerged total: {total} rows  (spam={spam_total}, ham={total-spam_total})")

    train_texts, test_texts, train_labels, test_labels = train_test_split(
        all_texts, all_labels, test_size=0.20, stratify=all_labels, random_state=42
    )

    # Dual TF-IDF: character n-grams (catch typos/obfuscation) + word n-grams (phrases)
    model = Pipeline([
        ("features", FeatureUnion([
            ("char_ngram", TV(
                analyzer="char_wb",
                ngram_range=(3, 5),
                min_df=2,
                sublinear_tf=True,
                max_features=80_000,
            )),
            ("word_ngram", TV(
                analyzer="word",
                ngram_range=(1, 2),
                min_df=2,
                sublinear_tf=True,
                max_features=40_000,
                token_pattern=r"(?u)\b\w+\b",
            )),
        ])),
        ("classifier", LogisticRegression(
            max_iter=2000,
            class_weight="balanced",
            C=1.5,
            solver="lbfgs",
            random_state=42,
        )),
    ])

    print("\nTraining…")
    model.fit(train_texts, train_labels)

    predictions = model.predict(test_texts)
    precision, recall, f1, _ = precision_recall_fscore_support(
        test_labels, predictions, average="binary", zero_division=0
    )
    acc = accuracy_score(test_labels, predictions)

    print("\n--- Evaluation ---")
    print(classification_report(test_labels, predictions, target_names=["ham", "spam"]))

    MODEL_DIRECTORY.mkdir(exist_ok=True)
    joblib.dump(model, MODEL_PATH)

    metadata = {
        "model": "dual TF-IDF (char 3-5gram + word 1-2gram) + Logistic Regression",
        "sources": source_counts,
        "dataset": "UCI SMS Spam Collection + India-first synthetic scam/ham data",
        "total_rows": total,
        "spam_rows": spam_total,
        "ham_rows": total - spam_total,
        "split": "80/20 stratified holdout, random_state=42",
        "metrics": {
            "accuracy": round(float(acc), 4),
            "spam_precision": round(float(precision), 4),
            "spam_recall": round(float(recall), 4),
            "spam_f1": round(float(f1), 4),
        },
        "trained_at_utc": datetime.now(UTC).isoformat(),
        "limitations": (
            "This model is a secondary signal in TrustLens. "
            "It does not change the evidence-weighted risk score. "
            "The synthetic India-specific data covers common scam patterns "
            "but is not a calibrated fraud detector."
        ),
    }
    INFO_PATH.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    print(json.dumps(metadata, indent=2))
    print(f"\nModel saved -> {MODEL_PATH}")


if __name__ == "__main__":
    main()
