import json
from pathlib import Path

import pytest

from app.analyzer import MAX_MESSAGE_LENGTH, analyze_message


def test_evaluation_cases_match_expected_score_ranges():
    cases = json.loads((Path(__file__).parents[1] / "data" / "evaluation_cases.json").read_text())
    for case in cases:
        result = analyze_message(case["message"], case["context"])
        if "expected_min_score" in case:
            assert result["risk_score"] >= case["expected_min_score"], case["id"]
        if "expected_max_score" in case:
            assert result["risk_score"] <= case["expected_max_score"], case["id"]


def test_evidence_references_exact_user_text():
    text = "Share your OTP now to finish KYC."
    result = analyze_message(text, "account")
    assert any(item["evidence"] == "Share your OTP" for item in result["findings"])


def test_repeated_urgency_is_deduplicated():
    one = analyze_message("Act now", "general")["risk_score"]
    repeated = analyze_message("Act now. Act now. Act now.", "general")["risk_score"]
    assert repeated == one


def test_empty_and_long_messages_are_rejected():
    with pytest.raises(ValueError):
        analyze_message("   ")
    with pytest.raises(ValueError):
        analyze_message("a" * (MAX_MESSAGE_LENGTH + 1))


def test_no_external_provider_required():
    result = analyze_message("Your statement is ready in the official app.", "account")
    assert result["mode"] == "local deterministic analysis"


def test_hinglish_secret_and_account_threat_are_detected():
    result = analyze_message("Apna OTP bata do, warna account band ho jayega.", "account")
    assert result["risk_label"] == "High risk"
    assert {item["id"] for item in result["findings"]} >= {"hinglish_secret", "hinglish_threat"}


def test_job_fee_changes_an_inconclusive_offer_to_possible_job_fraud():
    baseline = analyze_message("Work from home and earn Rs 5000 per day. Reply if interested.", "job")
    risky = analyze_message("Work from home and earn Rs 5000 per day. Pay Rs 299 registration fee today only for instant joining.", "job")
    assert baseline["risk_label"] == "No strong signals"
    assert baseline["classification"] == "inconclusive"
    assert risky["risk_score"] > baseline["risk_score"]
    assert risky["risk_label"] == "High risk"
    assert risky["classification"] == "possible job fraud"


def test_link_inspection_describes_but_never_fetches_a_url():
    result = analyze_message("Verify at https://secure-kyc-update.example/login", "phishing")
    assert result["link_checks"][0]["host"] == "secure-kyc-update.example"
    assert any("reserved .example" in signal for signal in result["link_checks"][0]["signals"])


def test_link_and_service_impersonation_corroborate_to_high_risk():
    result = analyze_message(
        "CourierHub: delivery is on hold. Update your address today at https://courier-verify.example/track to avoid return.",
        "phishing",
    )
    assert result["risk_score"] == 35
    assert result["risk_label"] == "High risk"


def test_optional_sms_evaluation_dataset_is_well_formed():
    """Guard the user-supplied evaluation fixture without treating it as training data."""
    import csv

    dataset = Path(__file__).parents[1] / "data" / "sms_spam_train.csv"
    with dataset.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert rows
    assert set(rows[0]) == {"sms", "label"}
    assert {row["label"] for row in rows} == {"0", "1"}
    assert all(row["sms"].strip() for row in rows)
