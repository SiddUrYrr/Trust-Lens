"""Deterministic, evidence-first scam analysis engine for TrustLens."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlparse

from .ai_explainer import ai_explain
from .ml_model import sms_ml_signal


MAX_MESSAGE_LENGTH = 8_000
Context = Literal["payment", "job", "phishing", "account", "general"]


@dataclass(frozen=True)
class Rule:
    key: str
    title: str
    explanation: str
    pattern: str
    severity: Literal["critical", "high", "medium", "low"]
    weight: int
    group: str
    contexts: tuple[str, ...] = ()


# Scores represent indicator severity, not a probability of fraud. Rules are deliberately
# combined into groups so repetitions (e.g. several uses of "urgent") do not inflate risk.
RULES = (
    Rule("otp_request", "OTP requested", "OTPs authorize access or payments. Legitimate support staff should never ask you to share one.", r"\b(?:share|send|provide|tell|reply with|forward)\s+(?:your\s+)?(?:otp|one[ -]?time (?:password|code)|verification code)\b", "critical", 35, "secrets"),
    Rule("pin_request", "UPI PIN requested", "A UPI PIN is used to approve a payment, not to receive money or verify an account.", r"\b(?:share|send|provide|enter|tell)\s+(?:your\s+)?(?:upi\s*)?pin\b|\bupi\s+pin\s+(?:to|for)\s+(?:receive|verify|claim)", "critical", 35, "secrets"),
    Rule("credential_request", "Credentials requested", "Requests for passwords or login credentials can enable account takeover.", r"\b(?:share|send|provide|enter|confirm)\s+(?:your\s+)?(?:password|login|user ?id|cvv|card number)\b", "critical", 32, "secrets"),
    Rule("payment_fee", "Advance fee or payment instruction", "Unexpected registration fees or instructions to pay before a promised service are common fraud patterns.", r"\b(?:registration|processing|activation|security|verification)\s+fee\b|\bpay\s+(?:₹|rs\.?|inr)?\s*\d+\b|\bsend\s+(?:₹|rs\.?|inr)?\s*\d+\b", "high", 22, "payment"),
    Rule("collect_request", "UPI collect request", "A collect request can debit your account when approved. Verify the payee independently before accepting.", r"\b(?:approve|accept|tap)\s+(?:the\s+)?(?:upi\s+)?collect\s+request\b|\bcollect\s+request\b", "high", 22, "payment"),
    Rule("unrealistic_job", "Unrealistic job promise", "High pay with little detail can be used to pressure applicants before an advance-fee request.", r"\b(?:earn|salary|income)\s+(?:₹|rs\.?|inr)?\s*\d{2,}\s*(?:per\s*)?(?:day|week|month)\b|\bwork\s+(?:from\s+)?home\b.{0,80}\b(?:no experience|instant joining|guaranteed)\b", "medium", 12, "job"),
    Rule("urgency", "Pressure to act quickly", "Time pressure can reduce the chance that someone verifies a request independently.", r"\b(?:urgent(?:ly)?|immediately|within\s+\d+\s*(?:minutes?|hours?)|today\s+only|last\s+warning|act\s+now)\b", "low", 4, "pressure"),
    Rule("threat", "Threat of loss", "Threats of blocking, suspension, or penalties are often used to force quick compliance.", r"\b(?:account|sim|upi|card)\s+(?:will be\s+)?(?:blocked|suspended|closed|deactivated)\b|\bavoid\s+(?:penalty|suspension|block)\b", "medium", 10, "pressure"),
    Rule("kyc", "KYC-related request", "KYC wording alone is not proof of fraud, but paired with secret or payment requests it warrants caution.", r"\b(?:re-?kyc|kyc\s+(?:update|verification|pending))\b", "low", 4, "kyc"),
    Rule("impersonation", "Possible service impersonation", "The message presents itself as a trusted service while requesting an action; verify through the official app or website.", r"\b(?:bank|customer\s+care|support\s+team|courier|delivery|income\s+tax|police)\b.{0,100}\b(?:share|send|pay|click|verify|update|call)\b", "medium", 12, "identity"),
    Rule("emergency_money", "Emergency money request", "Unexpected emergencies asking for money should be verified through a known contact channel before sending funds.", r"\b(?:accident|hospital|emergency|stranded)\b.{0,120}\b(?:send|transfer|need)\b.{0,80}\b(?:money|₹|rs\.?|inr)\b", "high", 20, "payment"),
    Rule("hinglish_secret", "OTP or PIN requested in Hinglish", "OTP and UPI PIN requests are unsafe in any language. Banks and support staff should not ask you to reveal them.", r"\b(?:apna\s+)?(?:otp|upi\s*pin|pin)\s+(?:bata(?:o|\s+do)?|bhej(?:o|\s+do)?|share\s+karo|send\s+karo)\b|\b(?:otp|upi\s*pin|pin)\s+(?:do|de\s+do)\b", "critical", 35, "secrets"),
    Rule("hinglish_fee", "Advance fee requested in Hinglish", "Job registration or processing fees should be verified independently before paying.", r"\b(?:registration|processing|joining)\s+fee\s*(?:₹|rs\.?|inr)?\s*\d+\b|\b(?:₹|rs\.?|inr)\s*\d+\s*(?:ka|ki)?\s*(?:registration|processing|joining)\s+fee\b", "high", 22, "payment"),
    Rule("hinglish_pressure", "Pressure to act quickly in Hinglish", "Words such as “turant” or “aaj hi” can be pressure tactics when paired with money or secret requests.", r"\b(?:turant|jaldi|abhi|aaj\s+hi)\b", "low", 4, "pressure"),
    Rule("hinglish_threat", "Account-blocking threat in Hinglish", "Threats that an account will be blocked can be used to rush a person into acting.", r"\b(?:account|sim|upi)\s+(?:band|block)\s+ho\s+(?:jayega|jaega)\b", "medium", 10, "pressure"),
)

URL_RE = re.compile(r"\b(?:https?://|www\.)[^\s<>()]+", re.IGNORECASE)
SUSPICIOUS_URL_RE = re.compile(r"(?:\b(?:verify|kyc|secure|update|claim|reward|login)\b|\b\d{1,3}(?:\.\d{1,3}){3}\b|\.(?:xyz|top|click|live|site)\b)", re.IGNORECASE)


def _snippet(text: str, start: int, end: int) -> str:
    return text[start:end]


def _label(score: int) -> str:
    # A single verified secret-request rule is already a severe safety concern (35),
    # while isolated pressure language remains deliberately below this boundary.
    if score >= 35:
        return "High risk"
    if score >= 15:
        return "Caution"
    return "No strong signals"


def _inspect_link(url: str) -> dict:
    """Describe observable URL properties without resolving, opening, or fetching it."""
    inspected = url.rstrip(".,;:!?")
    parsed = urlparse(inspected if "://" in inspected else f"//{inspected}")
    host = (parsed.hostname or "").lower()
    signals: list[str] = []
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
        signals.append("Uses a numeric IP address instead of a domain name")
    if "@" in inspected:
        signals.append("Contains @, which can disguise the real destination")
    if host.count(".") >= 3:
        signals.append("Uses multiple subdomains")
    if re.search(r"\.(?:xyz|top|click|live|site)$", host):
        signals.append("Uses an uncommon high-risk-style domain ending")
    lure_terms = re.findall(r"(?:verify|kyc|secure|update|claim|reward|login)", inspected, re.IGNORECASE)
    if lure_terms:
        signals.append(f"Contains security or verification wording: {', '.join(sorted(set(word.lower() for word in lure_terms)))}")
    if host.endswith(".example"):
        signals.append("Uses a reserved .example domain (safe fictional demo link)")
    return {"url": url, "host": host or "Unable to parse host", "signals": signals or ["No obvious structural URL signal found"]}


def _actions(context: str, risk: int, keys: set[str]) -> dict[str, list[str]]:
    do = ["Pause before responding or paying.", "Verify independently using the organisation's official app, website, or number you already trust."]
    dont = ["Do not share OTPs, passwords, UPI PINs, CVV details, or screen access.", "Do not open links or approve collect requests until independently verified."]
    verify = ["Use a trusted official channel—not a number or link supplied in this message."]
    if {"otp_request", "pin_request", "credential_request"} & keys:
        do.insert(1, "If you already shared a secret, contact your bank or service provider through its official channel immediately.")
    if context == "job" or "payment_fee" in keys:
        do.append("Research the employer independently and confirm the role through its public contact details.")
        dont.append("Do not pay a registration, processing, or activation fee for a job.")
        verify.append("Check the employer's official careers page and a known company number.")
    if context == "payment" or "collect_request" in keys or "pin_request" in keys:
        do.append("Check the recipient name and amount inside your UPI app before approving any request.")
        verify.append("Remember: receiving money never requires entering a UPI PIN.")
    if risk < 15:
        do = ["No strong scam pattern was detected in this text.", "Still verify unexpected requests before sharing information or making a payment."]
        dont = ["Do not treat this result as proof that a message is safe."]
        verify = ["Use a known official channel if the sender or request is unexpected."]
    return {"do": do[:4], "dont": dont[:3], "verify": verify[:3]}


def analyze_message(message: str, context: Context = "general") -> dict:
    """Analyze one message without storage, network calls, or unsafe rendering."""
    if not isinstance(message, str):
        raise ValueError("Message must be text.")
    text = message.strip()
    if not text:
        raise ValueError("Enter a message to analyze.")
    if len(text) > MAX_MESSAGE_LENGTH:
        raise ValueError(f"Message is too long. Limit is {MAX_MESSAGE_LENGTH:,} characters.")
    if context not in {"payment", "job", "phishing", "account", "general"}:
        context = "general"

    ml_signal = sms_ml_signal(text)
    findings: list[dict] = []
    group_best: dict[str, int] = {}
    for rule in RULES:
        match = re.search(rule.pattern, text, re.IGNORECASE | re.DOTALL)
        if not match:
            continue
        weight = rule.weight + (3 if rule.contexts and context in rule.contexts else 0)
        findings.append({
            "id": rule.key, "title": rule.title, "explanation": rule.explanation,
            "severity": rule.severity, "weight": weight, "evidence": _snippet(text, match.start(), match.end()),
            "start": match.start(), "end": match.end(), "group": rule.group,
        })
        group_best[rule.group] = max(group_best.get(rule.group, 0), weight)

    link_checks: list[dict] = []
    for match in URL_RE.finditer(text):
        url = match.group(0)
        inspection = _inspect_link(url)
        link_checks.append(inspection)
        suspicious = bool(SUSPICIOUS_URL_RE.search(url))
        weight = 16 if suspicious else 5
        findings.append({
            "id": "suspicious_link" if suspicious else "link_present",
            "title": "Suspicious-looking link" if suspicious else "Link present",
            "explanation": "This link uses terms or a domain style commonly used in credential lures. Inspect it only through a safe, independent channel." if suspicious else "A link is present. Its presence alone does not establish fraud; avoid opening unexpected links.",
            "severity": "high" if suspicious else "low", "weight": weight, "evidence": url,
            "start": match.start(), "end": match.end(), "group": "link",
        })
        group_best["link"] = max(group_best.get("link", 0), weight)

    score = sum(group_best.values())
    high_groups = sum(1 for weight in group_best.values() if weight >= 16)
    # Corroboration rewards distinct evidence groups (for example, a suspicious link
    # plus a service-impersonation claim), never repeated keywords in the same group.
    if high_groups >= 2:
        score += min(10, 3 * (high_groups - 1))
    elif high_groups == 1 and len(group_best) >= 2:
        score += 7
    score = min(97, score)

    # ML tie-breaker: the local model can elevate a Caution verdict to High Risk
    # when it is very confident the message is spam-like, but only within the
    # Caution band (15–34). This keeps the rule engine as the primary source.
    ml_boosted = False
    if ml_signal.get("available") and ml_signal.get("confidence") is not None:
        ml_conf = float(ml_signal["confidence"])
        if 15 <= score < 35 and ml_conf >= 0.80:
            score = 35
            ml_boosted = True

    keys = {f["id"] for f in findings}

    if not findings:
        classification = "inconclusive"
        reason = "No concrete scam indicators were found in the supplied text. That is not confirmation that it is safe."
    elif {"otp_request", "pin_request", "credential_request"} & keys:
        classification = "account-security or payment scam"
        reason = "The analysis found a request for a secret used to access an account or authorize payment."
    elif ("payment_fee" in keys or "hinglish_fee" in keys) and (context == "job" or "unrealistic_job" in keys):
        classification = "possible job fraud"
        reason = "The analysis found an advance-payment or unrealistic-job pattern."
    elif "collect_request" in keys or context == "payment":
        classification = "possible payment scam"
        reason = "The analysis found payment-related pressure or instructions that need independent verification."
    elif "suspicious_link" in keys or "kyc" in keys:
        classification = "possible phishing"
        reason = "The analysis found a link or verification pattern that can be used to capture account details."
    elif score < 15 or keys == {"unrealistic_job"}:
        classification = "inconclusive"
        reason = "The available evidence is limited and does not establish a scam pattern. Verify independently before acting."
    else:
        classification = "suspicious message"
        reason = "Multiple contextual indicators suggest caution, but this does not confirm fraud."


    confidence = min(0.92, 0.35 + (0.08 * len(group_best)) + (0.12 if any(f["severity"] == "critical" for f in findings) else 0))
    uncertainty = "Lower uncertainty" if confidence >= 0.7 else "Moderate uncertainty" if confidence >= 0.5 else "Higher uncertainty"

    sorted_findings = sorted(findings, key=lambda item: (-item["weight"], item["start"]))

    ai_explanation = ai_explain(text, sorted_findings, classification, score)

    scoring_note = "This is an evidence-weighted heuristic score, not a calibrated probability or confirmation of fraud."
    if ml_boosted:
        scoring_note += " The local ML model elevated this verdict from Caution to High Risk."

    return {
        "risk_score": score, "risk_label": _label(score), "classification": classification,
        "summary": reason, "confidence": round(confidence, 2), "uncertainty": uncertainty,
        "findings": sorted_findings,
        "link_checks": link_checks,
        "ml_signal": ml_signal,
        "ml_boosted": ml_boosted,
        "ai_explanation": ai_explanation,
        "actions": _actions(context, score, keys), "mode": "local deterministic analysis",
        "scoring_note": scoring_note,
    }
