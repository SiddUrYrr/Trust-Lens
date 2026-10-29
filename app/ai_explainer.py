"""Optional Gemini-powered natural language explanation for TrustLens findings.

This module is fully optional. If GEMINI_API_KEY is not set in the environment,
all functions return a graceful fallback dict with available=False.
No message text is ever sent anywhere without an API key being explicitly configured.
"""
from __future__ import annotations

import os
import requests

GEMINI_MODELS = ("gemini-3.5-flash-lite", "gemini-3.5-flash", "gemini-flash-latest")
API_ENDPOINT = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={key}"


def _get_api_key() -> str | None:
    api_key = os.environ.get("GEMINI_API_KEY", "").strip()
    if not api_key or api_key == "your_gemini_api_key_here":
        return None
    return api_key


def _get_model():
    """Helper used by health checks to confirm if an API key is configured."""
    return _get_api_key()


def ai_explain(message: str, findings: list[dict], classification: str, risk_score: int) -> dict:
    """Generate a plain-English safety explanation using Gemini via HTTP API.

    Falls back gracefully with available=False when:
    - GEMINI_API_KEY is not set
    - The API call fails or times out
    """
    key = _get_api_key()
    if not key:
        return {
            "available": False,
            "explanation": None,
            "note": "Add GEMINI_API_KEY to a .env file to enable AI-powered explanations.",
        }

    evidence_lines = "\n".join(
        f'- {f["title"]}: "{f["evidence"]}" (severity: {f["severity"]})'
        for f in findings[:6]
    ) or "- No specific evidence found."

    prompt = (
        "You are TrustLens, a digital safety assistant for India.\n"
        "A user submitted a message for scam analysis. The rule engine has already run.\n\n"
        f'Message: "{message[:400]}"\n\n'
        f"Findings:\n{evidence_lines}\n\n"
        f"Classification: {classification}\n"
        f"Risk score: {risk_score}/100\n\n"
        "Write a plain-text safety explanation in exactly 2-3 sentences (max 75 words).\n"
        "Rules:\n"
        "- Explain what specifically makes this message suspicious, or clearly say it looks safe.\n"
        "- Use simple language any Indian user can understand (no jargon).\n"
        "- Do NOT use markdown, bullet points, or headings.\n"
        "- Do NOT start with 'I' or refer to yourself.\n"
        "- If safe or inconclusive, say so clearly and tell the user not to assume safety.\n"
        "- If scam, name the type (OTP fraud, job scam, phishing, etc.)."
    )

    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.25,
            "maxOutputTokens": 160,
        },
    }

    last_error = ""
    for model_name in GEMINI_MODELS:
        url = API_ENDPOINT.format(model=model_name, key=key)
        try:
            res = requests.post(url, json=payload, timeout=12)
            if res.status_code == 200:
                data = res.json()
                candidates = data.get("candidates", [])
                if candidates:
                    parts = candidates[0].get("content", {}).get("parts", [])
                    if parts and "text" in parts[0]:
                        explanation = parts[0]["text"].strip()
                        return {
                            "available": True,
                            "explanation": explanation,
                            "note": f"AI explanation by Gemini ({model_name}). Always verify independently before acting.",
                        }
            else:
                last_error = f"HTTP {res.status_code}"
        except Exception as exc:
            last_error = type(exc).__name__
            continue

    return {
        "available": False,
        "explanation": None,
        "note": f"AI explanation temporarily unavailable ({last_error or 'timeout'}).",
    }
