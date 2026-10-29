# TrustLens 🔍

**Evidence-First Digital Safety Workspace for Suspicious Messages**  
*Hackathon Theme: Cybersecurity · Generative AI · Digital Safety*

---

## 📌 Overview

**TrustLens** is a local-first, explainable digital-safety application designed to protect users from modern financial and digital scams. Unlike black-box detectors that output arbitrary confidence scores, TrustLens points directly to the exact phrases that warrant concern—such as OTP demands, UPI PIN traps, fake KYC alerts, advance-fee job offers, and deceptive links—and couples them with actionable advice and generative AI explanations.

Designed with an **India-first perspective**, TrustLens understands local payment systems (UPI, collect requests, PIN-to-receive fallacies), banking workflows (KYC, account freeze threats), and common bilingual phrasing (**Hinglish**).

---

## 🎯 Hackathon Theme Alignment

| Theme Pillar | Implementation in TrustLens |
| :--- | :--- |
| **🛡️ Cybersecurity** | Grounded pattern matching across 15+ threat vectors, non-resolving observable URL inspection, deduplicated heuristic risk scoring (0–100), and anti-tampering principles. |
| **🤖 Generative AI** | Integrated **Gemini 1.5/3.5 Flash** layer that translates low-level cryptographic/cybersecurity signals into clear, plain-language safety summaries for everyday users—with complete offline fallback. |
| **🔒 Digital Safety & Privacy** | Local-by-default architecture: raw message text is never logged to server disk or third-party storage. Client-side rendering is strictly XSS-safe using DOM text nodes. |

---

## 🏗️ Architecture & Data Flow

```text
                               ┌────────────────────────────────────────────────────────┐
                               │                    TrustLens Web UI                    │
                               │   (Safe DOM Rendering, Context Tabs, Interactive Lab)   │
                               └───────────────────────────┬────────────────────────────┘
                                                           │ POST /api/analyze
                                                           ▼
                               ┌────────────────────────────────────────────────────────┐
                               │                   FastAPI Backend                      │
                               │                  (app/main.py)                         │
                               └─────────────┬────────────────────────────┬─────────────┘
                                             │                            │
                                             ▼                            ▼
                 ┌───────────────────────────────────────┐   ┌──────────────────────────┐
                 │       Deterministic Rule Engine       │   │   Trained Local ML Model │
                 │          (app/analyzer.py)            │   │      (app/ml_model.py)   │
                 │  - 15 Threat Rules + Deduplication    │   │  - 7,934 Samples         │
                 │  - Observable URL Inspector           │   │  - Dual TF-IDF Pipeline  │
                 │  - Contextual Risk Scorer             │   │  - 99.18% Accuracy       │
                 │  - ML Tie-Breaker Logic               │   └────────────┬─────────────┘
                 └───────────────────┬───────────────────┘                │
                                     │                                    │
                                     ├────────────────────────────────────┘
                                     ▼
                 ┌───────────────────────────────────────┐
                 │        Gemini GenAI Explainer         │
                 │        (app/ai_explainer.py)          │
                 │  - Plain-Language Synthesis           │
                 │  - Graceful Fallback if Offline       │
                 └───────────────────┬───────────────────┘
                                     ▼
                 ┌───────────────────────────────────────┐
                 │       Structured Safety Verdict       │
                 │ (Evidence Lens, Score, Actions, AI)   │
                 └───────────────────────────────────────┘
```

---

## ✨ Key Features

* **Evidence Lens (DOM-Safe Highlighting)**: Highlights exact suspicious phrases without unsafe `innerHTML` injection, avoiding XSS vulnerabilities.
* **Dual-Signal Engine & ML Tie-Breaker**: Combines deterministic rules with a locally trained statistical model. If rule matching indicates "Caution" but the local ML model detects $\ge$80% spam phrasing, the verdict is elevated to "High Risk" with an explicit annotation.
* **Gemini Safety Explanations**: Produces succinct (2–3 sentence) contextual breakdowns in plain English, ensuring non-technical users immediately grasp *why* a message is dangerous.
* **Safe Observable Link Inspection**: Analyzes observable URL characteristics (IP address hosts, high-risk TLDs like `.xyz` or `.click`, multi-subdomains, credential lure keywords) **without ever pinging, resolving, or fetching the target URL**.
* **Actionable Guidance Matrix**: Generates tailored `What to do`, `What not to do`, and `Verify independently` checklists based on detected evidence.
* **Hinglish & Localized Threat Detection**: Tailored rules capture colloquial urgency and fraud patterns (e.g., *"Apna OTP batao"*, *"account band ho jayega"*, *"aaj hi registration fee bhejo"*).
* **Privacy-Preserving Session History**: Stores analysis metadata in the local browser tab session only; raw messages are never retained in history.

---

## 🚀 Quickstart

### Prerequisites
* Python 3.11+ (Tested on Python 3.11, 3.12, 3.14)
* A modern web browser

### 1. Clone & Set Up Environment
```powershell
# Create and activate virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt
```

### 2. Configure Environment (Optional)
To enable real-time Gemini AI explanations, create a `.env` file in the root directory:
```env
GEMINI_API_KEY=your_gemini_api_key_here
```
*(If no API key is provided, TrustLens automatically operates in fully offline deterministic mode with zero errors).*

### 3. Launch the Application
```powershell
python -m uvicorn app.main:app --reload
```
Open **`http://127.0.0.1:8000`** in your browser.

---

## 🧪 Testing & Validation

The test suite validates score bounds, deduplication integrity, Hinglish rules, link safety, and input boundaries:

```powershell
python -m pytest tests/ -v
```

All 10 core integration tests pass with zero warnings:
* `test_evaluation_cases_match_expected_score_ranges`
* `test_evidence_references_exact_user_text`
* `test_repeated_urgency_is_deduplicated`
* `test_empty_and_long_messages_are_rejected`
* `test_no_external_provider_required`
* `test_hinglish_secret_and_account_threat_are_detected`
* `test_job_fee_changes_an_inconclusive_offer_to_possible_job_fraud`
* `test_link_inspection_describes_but_never_fetches_a_url`
* `test_link_and_service_impersonation_corroborate_to_high_risk`
* `test_optional_sms_evaluation_dataset_is_well_formed`

---

## 📊 Machine Learning Model Details

TrustLens features a high-performance local SMS classifier:

| Parameter | Specification |
| :--- | :--- |
| **Architecture** | Dual FeatureUnion: Char $n$-gram (3–5) + Word $n$-gram (1–2) + Logistic Regression |
| **Training Data** | 7,934 Merged Samples (5,574 UCI SMS Spam + 2,360 Synthetic India Scam/Ham) |
| **Accuracy** | **99.18%** |
| **Spam Precision** | **99.48%** |
| **Spam Recall** | **97.19%** |
| **Spam F1-Score** | **98.32%** |
| **Storage** | Local artifact in `models/sms_spam_model.joblib` |

### Retraining the Model
To regenerate the synthetic India scam corpus and retrain the model locally:
```powershell
python scripts/generate_india_scam_data.py
python scripts/train_sms_model.py
```

---

## 📂 Project Structure

```text
buildacthon/
├── app/
│   ├── __init__.py
│   ├── main.py                # FastAPI endpoints, static asset mounts & health check
│   ├── analyzer.py            # Rule engine, scoring logic, link inspector & ML tie-breaker
│   ├── ai_explainer.py        # Gemini GenAI explanation client with offline fallback
│   └── ml_model.py            # Local scikit-learn model loader and probability scorer
├── data/
│   ├── evaluation_cases.json   # Synthetic test cases with score thresholds
│   ├── india_scam_synthetic.csv# Generated India-first scam & legitimate SMS dataset
│   └── sms_spam_train.csv     # UCI SMS spam collection fixture
├── models/
│   ├── sms_spam_model.joblib  # Trained model binary
│   └── sms_spam_model_info.json# Model metadata, metrics, and training timestamps
├── scripts/
│   ├── generate_india_scam_data.py # Synthetic data generation script
│   └── train_sms_model.py     # Pipeline trainer & evaluation script
├── tests/
│   └── test_analyzer.py       # Pytest test suite
├── web/
│   ├── index.html             # Single-page UI structure
│   ├── styles.css             # Responsive dark-theme styling & AI card styles
│   └── app.js                 # Frontend state, API integration, rendering & report export
├── .env.example               # Template for environment configuration
├── requirements.txt           # Python package requirements
├── test_messages.md           # 32 Curated test cases across all categories
└── README.md                  # Project documentation

---

## 📄 License & Responsible Use

TrustLens is developed for educational, evaluation, and defensive digital-safety demonstrations. It provides decision support based on observable text patterns and should not be considered legal or financial fraud certification. If you suspect active financial fraud in India, report it immediately to your bank and through the National Cyber Crime Reporting Portal (`cybercrime.gov.in` / Helpline `1930`).
