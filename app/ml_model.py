"""Local statistical SMS signal used as a secondary input to TrustLens."""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

import joblib


ROOT = Path(__file__).resolve().parent.parent
MODEL_PATH = ROOT / "models" / "sms_spam_model.joblib"
MODEL_INFO_PATH = ROOT / "models" / "sms_spam_model_info.json"


@lru_cache(maxsize=1)
def _load_model():
    try:
        return joblib.load(MODEL_PATH)
    except (FileNotFoundError, OSError, ValueError, ImportError):
        return None


@lru_cache(maxsize=1)
def _load_info() -> dict:
    try:
        return json.loads(MODEL_INFO_PATH.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, ValueError):
        return {}


def sms_ml_signal(message: str) -> dict:
    """Return a local model signal; it never sends message text to another service."""
    try:
        model = _load_model()
        if model is None:
            return {
                "available": False,
                "label": "Unavailable",
                "confidence": None,
                "note": "The optional local SMS model is unavailable; rule-based analysis is still active.",
            }
        probabilities = model.predict_proba([message])[0]
        classes = list(model.classes_)
        spam_probability = float(probabilities[classes.index(1)])
        if spam_probability >= 0.80:
            label = "Spam-like SMS pattern"
        elif spam_probability >= 0.55:
            label = "Mixed SMS pattern"
        else:
            label = "No strong spam pattern"
        return {
            "available": True,
            "label": label,
            "confidence": round(spam_probability, 2),
            "note": "Local model confidence for the SMS spam label, not a scam probability. It is a secondary signal and does not change the evidence-weighted risk score.",
            "dataset": _load_info().get("dataset", "SMS Spam Collection"),
        }
    except Exception as exc:
        return {
            "available": False,
            "label": "Unavailable",
            "confidence": None,
            "note": f"Local model unavailable ({type(exc).__name__}). Rule analysis remains active.",
            "dataset": _load_info().get("dataset", "SMS Spam Collection"),
        }
