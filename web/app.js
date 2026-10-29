const samples = [
  {type:"Account security", title:"Fake KYC update", context:"account", message:"Dear customer, your KYC is pending. Share your OTP immediately to avoid account blocked."},
  {type:"UPI / payment", title:"Fraudulent collect request", context:"payment", message:"I am from QuickPay support. Approve the UPI collect request to receive your cashback. Enter your UPI PIN to claim it."},
  {type:"Job / recruitment", title:"Work-from-home fee", context:"job", message:"Work from home, earn Rs 5000 per day. Pay Rs 299 registration fee today only for instant joining."},
  {type:"Phishing link", title:"Courier delivery lure", context:"phishing", message:"CourierHub: delivery is on hold. Update your address today at https://courier-verify.example/track to avoid return."},
  {type:"UPI / payment", title:"Fake support agent", context:"payment", message:"Customer care here. To receive your refund, enter your UPI PIN now. Your case expires in 10 minutes."},
  {type:"General", title:"Emergency impersonation", context:"general", message:"Hi, this is Rohan's colleague. He had an accident and needs money urgently. Send Rs 8000 to this number now."},
  {type:"Account security", title:"Legitimate bank alert", context:"account", message:"Your bank statement for October is ready in the official mobile banking app. Do not share OTPs with anyone."},
  {type:"General", title:"Ambiguous message", context:"general", message:"Hi, please call me when you are free. I need to discuss a payment."}
];

const quickSamples = {
  kyc: { context: "account", message: "Dear customer, your KYC is pending. Share your OTP immediately to avoid account blocked." },
  job: { context: "job", message: "Work from home, earn Rs 5000 per day. Pay Rs 299 registration fee today only for instant joining." },
  upi: { context: "payment", message: "I am from QuickPay support. Approve the UPI collect request to receive your cashback. Enter your UPI PIN to claim it." },
  delivery: { context: "phishing", message: "CourierHub: delivery is on hold. Update your address today at https://courier-verify.example/track to avoid return." },
  safe: { context: "general", message: "Hi Maya, just confirming dinner at 7 tonight. I booked our usual table. Let me know if you need to change the time!" }
};

let context = "general";
let current = null;
let history = [];
let toastTimer;

const el = (id) => document.getElementById(id);
const message = el("message");

const contextPrompts = {
  payment: "Paste a UPI request, payment instruction, refund message, or collect-request text here…",
  job: "Paste a job offer, recruitment message, salary promise, or fee request here…",
  phishing: "Paste a suspicious link, delivery alert, verification request, or email text here…",
  account: "Paste a KYC update, account alert, OTP request, or security message here…",
  general: "Paste an SMS, WhatsApp message, email, job offer, or payment request here…"
};

const contextHints = {
  payment: "UPI / payment — collect requests, refunds, payment instructions, and PIN-related messages.",
  job: "Job offer — salary promises, remote tasks, interview requests, and advance-fee messages.",
  phishing: "Phishing link — links, delivery updates, verification prompts, and login requests.",
  account: "Account security — KYC, OTP, login, account-blocking, and security alert messages.",
  general: "General message — SMS, WhatsApp messages, emails, or anything that does not fit a specific category."
};

function toast(msgText) {
  const t = el("toast");
  if (!t) return;
  t.textContent = msgText;
  t.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove("show"), 2400);
}

function setContext(next) {
  context = next;
  message.placeholder = contextPrompts[next] || contextPrompts.general;
  el("contextHint").textContent = contextHints[next] || contextHints.general;
  document.querySelectorAll("[data-context]").forEach(b => b.classList.toggle("selected", b.dataset.context === next));
  invalidateAnalysis();
}

document.querySelectorAll("[data-context]").forEach(button => {
  button.addEventListener("click", () => setContext(button.dataset.context));
});

function invalidateAnalysis() {
  if (!current) return;
  current = null;
  el("result").classList.add("hidden");
  el("emptyResult").classList.remove("hidden");
  const riskFill = el("riskFill");
  if (riskFill) riskFill.style.width = "0%";
  const resultFoot = el("resultFoot");
  if (resultFoot) resultFoot.textContent = "INSIGHTS APPEAR HERE";
}

message.addEventListener("input", () => {
  el("charCount").textContent = `${message.value.length.toLocaleString()} / 8,000`;
  invalidateAnalysis();
});

message.addEventListener("keydown", (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
    analyze();
  }
});

el("clearBtn").addEventListener("click", () => {
  message.value = "";
  message.dispatchEvent(new Event("input"));
  invalidateAnalysis();
  message.focus();
  toast("Message cleared");
});

document.querySelectorAll("[data-quick]").forEach(chip => {
  chip.addEventListener("click", () => {
    const item = quickSamples[chip.dataset.quick];
    if (item) {
      message.value = item.message;
      message.dispatchEvent(new Event("input"));
      setContext(item.context);
      message.focus();
      toast("Sample loaded. Click 'Check this message' to inspect.");
    }
  });
});

function escapeText(text) {
  const node = document.createElement("span");
  node.textContent = text;
  return node.innerHTML;
}

function highlight(text, findings) {
  const ranges = findings.map(f => ({ start: f.start, end: f.end })).sort((a, b) => a.start - b.start || b.end - a.end);
  let html = "", pos = 0;
  for (const range of ranges) {
    if (range.start < pos) continue;
    html += escapeText(text.slice(pos, range.start));
    html += `<mark class="evidence-mark">${escapeText(text.slice(range.start, range.end))}</mark>`;
    pos = range.end;
  }
  return html + escapeText(text.slice(pos));
}

function list(items, target) {
  el(target).innerHTML = `<ul>${items.map(x => `<li>${escapeText(x)}</li>`).join("")}</ul>`;
}

function renderLinkChecks(checks) {
  const container = el("linkChecks");
  if (!checks || !checks.length) {
    container.classList.add("hidden");
    return;
  }
  container.classList.remove("hidden");
  container.innerHTML = `<h2>Observed URL signals</h2><p>Links are never opened, resolved, or fetched by TrustLens.</p>${checks.map(check => `<div class="link-row"><strong>${escapeText(check.host)}</strong><ul>${check.signals.map(signal => `<li>${escapeText(signal)}</li>`).join("")}</ul></div>`).join("")}`;
}

function display(result, rawMessage) {
  current = { result, rawMessage };
  el("emptyResult").classList.add("hidden");
  el("result").classList.remove("hidden");

  const score = result.risk_score;
  const kind = score >= 65 ? "high" : score >= 35 ? "mid" : "low";

  const verdict = el("verdict");
  if (verdict) verdict.className = `verdict ${kind}`;

  const riskFill = el("riskFill");
  if (riskFill) {
    riskFill.className = `risk-fill ${kind}`;
    requestAnimationFrame(() => {
      riskFill.style.width = `${score}%`;
    });
  }

  el("riskLabel").textContent = result.risk_label;
  el("score").textContent = score;
  el("summary").textContent = result.summary;
  el("classification").textContent = result.classification;
  el("scoringNote").textContent = result.scoring_note;
  el("confidence").textContent = `${Math.round(result.confidence * 100)}%`;
  el("uncertainty").textContent = result.uncertainty;

  const ml = result.ml_signal || { available: false, label: "Unavailable", note: "No local SMS model signal." };
  el("mlLabel").textContent = ml.available && ml.confidence !== null ? `${ml.label} · ${Math.round(ml.confidence * 100)}%` : ml.label;
  el("mlNote").textContent = ml.note;

  const ai = result.ai_explanation || { available: false };
  const aiCard = el("aiCard");
  if (ai.available && ai.explanation) {
    aiCard.classList.remove("hidden");
    el("aiText").textContent = ai.explanation;
    el("aiNote").textContent = ai.note || "";
  } else {
    aiCard.classList.add("hidden");
  }

  el("highlightedMessage").innerHTML = highlight(rawMessage, result.findings);
  el("findingCount").textContent = `${result.findings.length} finding${result.findings.length === 1 ? "" : "s"}`;

  el("findings").innerHTML = result.findings.length ? result.findings.map(f => {
    return `<article class="finding ${f.severity}"><span class="finding-dot">!</span><div><strong>${escapeText(f.title)}</strong><p>${escapeText(f.explanation)}</p></div><code>${escapeText(f.evidence)}</code></article>`;
  }).join("") : `<div class="signal"><span class="signal-icon" style="background:var(--green-pale);color:var(--green)">✓</span><div><strong>No common warning signs detected.</strong><p>Automated checks found no known scam patterns, but always verify unexpected requests independently.</p></div></div>`;

  renderLinkChecks(result.link_checks || []);
  list(result.actions.do, "doList");
  list(result.actions.dont, "dontList");
  list(result.actions.verify, "verifyList");

  const count = result.findings.length;
  const resultFoot = el("resultFoot");
  if (resultFoot) {
    resultFoot.textContent = `${count} SIGNAL${count === 1 ? "" : "S"} · ${result.mode.toUpperCase()}`;
  }

  history.unshift({
    label: result.risk_label,
    score: result.risk_score,
    classification: result.classification,
    time: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
  });
  history = history.slice(0, 8);
  renderHistory();

  el("result").scrollIntoView({ behavior: "smooth", block: "nearest" });
}

// In-browser fallback engine for offline or standalone client preview
const clientRules = [
  { id: "otp_request", title: "OTP requested", explanation: "OTPs authorize access or payments. Legitimate support staff should never ask you to share one.", re: /(?:share|send|provide|tell|reply with|forward)\s+(?:your\s+)?(?:otp|one[ -]?time (?:password|code)|verification code)/i, severity: "critical", weight: 35, group: "secrets" },
  { id: "pin_request", title: "UPI PIN requested", explanation: "A UPI PIN is used to approve a payment, not to receive money or verify an account.", re: /(?:share|send|provide|enter|tell)\s+(?:your\s+)?(?:upi\s*)?pin|\bupi\s+pin\s+(?:to|for)\s+(?:receive|verify|claim)/i, severity: "critical", weight: 35, group: "secrets" },
  { id: "credential_request", title: "Credentials requested", explanation: "Requests for passwords or login credentials can enable account takeover.", re: /(?:share|send|provide|enter|confirm)\s+(?:your\s+)?(?:password|login|user ?id|cvv|card number)/i, severity: "critical", weight: 32, group: "secrets" },
  { id: "payment_fee", title: "Advance fee or payment instruction", explanation: "Unexpected registration fees or instructions to pay before a promised service are common fraud patterns.", re: /(?:registration|processing|activation|security|verification|onboarding)\s+fee|pay\s+(?:₹|rs\.?|inr|\$)?\s*\d+|send\s+(?:₹|rs\.?|inr|\$)?\s*\d+/i, severity: "high", weight: 22, group: "payment" },
  { id: "collect_request", title: "UPI collect request", explanation: "A collect request can debit your account when approved. Verify the payee independently before accepting.", re: /(?:approve|accept|tap)\s+(?:the\s+)?(?:upi\s+)?collect\s+request|collect\s+request/i, severity: "high", weight: 22, group: "payment" },
  { id: "unrealistic_job", title: "Unrealistic job promise", explanation: "High pay with little detail can be used to pressure applicants before an advance-fee request.", re: /(?:earn|salary|income)\s+(?:₹|rs\.?|inr|\$)?\s*\d{2,}\s*(?:per\s*)?(?:day|week|month)|work\s+(?:from\s+)?home.{0,80}(?:no experience|instant joining|guaranteed|no interview)/i, severity: "medium", weight: 12, group: "job" },
  { id: "urgency", title: "Pressure to act quickly", explanation: "Time pressure can reduce the chance that someone verifies a request independently.", re: /(?:urgent(?:ly)?|immediately|within\s+\d+\s*(?:minutes?|hours?)|today\s+only|last\s+warning|act\s+now|hurry|expires?)/i, severity: "low", weight: 4, group: "pressure" },
  { id: "threat", title: "Threat of loss", explanation: "Threats of blocking, suspension, or penalties are often used to force quick compliance.", re: /(?:account|sim|upi|card)\s+(?:will be\s+)?(?:blocked|suspended|closed|deactivated)|avoid\s+(?:penalty|suspension|block)/i, severity: "medium", weight: 10, group: "pressure" },
  { id: "kyc", title: "KYC-related request", explanation: "KYC wording alone is not proof of fraud, but paired with secret or payment requests it warrants caution.", re: /(?:re-?kyc|kyc\s+(?:update|verification|pending))/i, severity: "low", weight: 4, group: "kyc" },
  { id: "impersonation", title: "Possible service impersonation", explanation: "The message presents itself as a trusted service while requesting an action; verify through the official app or website.", re: /(?:bank|customer\s+care|support\s+team|courier|delivery|income\s+tax|police|usps).{0,100}(?:share|send|pay|click|verify|update|call)/i, severity: "medium", weight: 12, group: "identity" },
  { id: "emergency_money", title: "Emergency money request", explanation: "Unexpected emergencies asking for money should be verified through a known contact channel before sending funds.", re: /(?:accident|hospital|emergency|stranded).{0,120}(?:send|transfer|need).{0,80}(?:money|₹|rs\.?|inr|\$)/i, severity: "high", weight: 20, group: "payment" },
  { id: "hinglish_secret", title: "OTP or PIN requested in Hinglish", explanation: "OTP and UPI PIN requests are unsafe in any language. Banks and support staff should not ask you to reveal them.", re: /(?:apna\s+)?(?:otp|upi\s*pin|pin)\s+(?:bata(?:o|\s+do)?|bhej(?:o|\s+do)?|share\s+karo|send\s+karo)|(?:otp|upi\s*pin|pin)\s+(?:do|de\s+do)/i, severity: "critical", weight: 35, group: "secrets" },
  { id: "hinglish_fee", title: "Advance fee requested in Hinglish", explanation: "Job registration or processing fees should be verified independently before paying.", re: /(?:registration|processing|joining)\s+fee\s*(?:₹|rs\.?|inr)?\s*\d+|(?:₹|rs\.?|inr)\s*\d+\s*(?:ka|ki)?\s*(?:registration|processing|joining)\s+fee/i, severity: "high", weight: 22, group: "payment" },
  { id: "hinglish_threat", title: "Account-blocking threat in Hinglish", explanation: "Threats that an account will be blocked can be used to rush a person into acting.", re: /(?:account|sim|upi)\s+(?:band|block)\s+ho\s+(?:jayega|jaega)/i, severity: "medium", weight: 10, group: "pressure" },
];

function clientAnalyze(text, ctx) {
  const findings = [];
  const groupBest = {};
  for (const rule of clientRules) {
    const m = text.match(rule.re);
    if (!m) continue;
    const start = m.index;
    const end = start + m[0].length;
    findings.push({
      id: rule.id,
      title: rule.title,
      explanation: rule.explanation,
      severity: rule.severity,
      weight: rule.weight,
      evidence: m[0],
      start,
      end,
      group: rule.group
    });
    groupBest[rule.group] = Math.max(groupBest[rule.group] || 0, rule.weight);
  }

  const urlMatches = text.match(/\b(?:https?:\/\/|www\.)[^\s<>()]+/gi) || [];
  const linkChecks = [];
  for (const url of urlMatches) {
    const isSuspicious = /(?:verify|kyc|secure|update|claim|reward|login|\.(?:xyz|top|click|live|site))\b/i.test(url);
    const weight = isSuspicious ? 16 : 5;
    const start = text.indexOf(url);
    const end = start + url.length;
    findings.push({
      id: isSuspicious ? "suspicious_link" : "link_present",
      title: isSuspicious ? "Suspicious-looking link" : "Link present",
      explanation: isSuspicious ? "This link uses terms or patterns commonly associated with phishing lures." : "A link was found in the message.",
      severity: isSuspicious ? "high" : "low",
      weight,
      evidence: url,
      start,
      end,
      group: "link"
    });
    groupBest["link"] = Math.max(groupBest["link"] || 0, weight);
    try {
      const parsed = new URL(url.startsWith("http") ? url : "https://" + url);
      linkChecks.push({
        url,
        host: parsed.hostname,
        signals: isSuspicious ? ["Contains verification/claim keywords or unusual domain"] : ["Standard link structure"]
      });
    } catch {
      linkChecks.push({ url, host: "url-link", signals: ["Web link present"] });
    }
  }

  let score = Object.values(groupBest).reduce((a, b) => a + b, 0);
  const highGroups = Object.values(groupBest).filter(w => w >= 16).length;
  if (highGroups >= 2) score += Math.min(10, 3 * (highGroups - 1));
  else if (highGroups === 1 && Object.keys(groupBest).length >= 2) score += 7;
  score = Math.min(97, score);

  const riskLabel = score >= 35 ? "High risk" : score >= 15 ? "Caution" : "No strong signals";
  const keys = new Set(findings.map(f => f.id));

  let classification = "inconclusive";
  let summary = "No concrete scam indicators were found in the supplied text. That is not confirmation that it is safe.";
  if (keys.has("otp_request") || keys.has("pin_request") || keys.has("credential_request") || keys.has("hinglish_secret")) {
    classification = "account-security or payment scam";
    summary = "The analysis found a request for a secret used to access an account or authorize payment.";
  } else if ((keys.has("payment_fee") || keys.has("hinglish_fee")) && (ctx === "job" || keys.has("unrealistic_job"))) {
    classification = "possible job fraud";
    summary = "The analysis found an advance-payment or unrealistic-job pattern.";
  } else if (keys.has("collect_request") || ctx === "payment") {
    classification = "possible payment scam";
    summary = "The analysis found payment-related pressure or instructions that need independent verification.";
  } else if (keys.has("suspicious_link") || keys.has("kyc")) {
    classification = "possible phishing";
    summary = "The analysis found a link or verification pattern that can be used to capture account details.";
  } else if (score >= 15) {
    classification = "suspicious message";
    summary = "Multiple contextual indicators suggest caution, but this does not confirm fraud.";
  }

  const confidence = Math.min(0.92, 0.35 + (0.08 * Object.keys(groupBest).length) + (findings.some(f => f.severity === "critical") ? 0.12 : 0));
  const uncertainty = confidence >= 0.7 ? "Lower uncertainty" : confidence >= 0.5 ? "Moderate uncertainty" : "Higher uncertainty";

  const doActions = ["Pause before responding or paying.", "Verify independently using an official app or known contact channel."];
  const dontActions = ["Do not share OTPs, passwords, UPI PINs, or card details.", "Do not open unverified links."];
  const verifyActions = ["Use a trusted official channel—never contact details from this message."];

  return {
    risk_score: score,
    risk_label: riskLabel,
    classification,
    summary,
    confidence: Math.round(confidence * 100) / 100,
    uncertainty,
    findings: findings.sort((a, b) => b.weight - a.weight),
    link_checks: linkChecks,
    ml_signal: { available: false, label: "Unavailable (in-browser mode)", note: "Local ML runs when backend server is active." },
    ai_explanation: { available: false },
    actions: { do: doActions, dont: dontActions, verify: verifyActions },
    mode: "in-browser local analysis",
    scoring_note: "Analyzed directly in your browser. (Run 'python -m uvicorn app.main:app' for server ML and AI explanations)."
  };
}

async function analyze() {
  const raw = message.value.trim();
  el("error").textContent = "";
  if (!raw) {
    el("error").textContent = "Please enter or paste a message to analyze.";
    toast("Please enter a message to analyze.");
    message.focus();
    return;
  }
  const button = el("analyzeBtn");
  button.disabled = true;
  button.innerHTML = `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="spin"><circle cx="12" cy="12" r="10"/></svg> Inspecting evidence…`;

  try {
    let result = null;
    let usingFallback = false;

    try {
      const res = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: raw, context })
      });

      const contentType = res.headers.get("content-type") || "";
      if (res.ok && contentType.includes("application/json")) {
        result = await res.json();
      } else {
        let errMsg = `Server returned status ${res.status}`;
        try {
          if (contentType.includes("application/json")) {
            const errBody = await res.json();
            errMsg = errBody.detail || errBody.message || errMsg;
          }
        } catch { /* ignore */ }
        console.warn("Backend API warning:", errMsg, "— falling back to in-browser engine.");
        usingFallback = true;
      }
    } catch (netErr) {
      console.warn("Backend unreachable:", netErr, "— falling back to in-browser engine.");
      usingFallback = true;
    }

    if (usingFallback || !result) {
      result = clientAnalyze(raw, context);
      toast("Analyzed using in-browser safety engine");
    }

    display(result, raw);
  } catch (err) {
    el("error").textContent = err.message || "An error occurred during analysis.";
    toast("Analysis failed: " + (err.message || "Unknown error"));
  } finally {
    button.disabled = false;
    button.innerHTML = `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="10.8" cy="10.8" r="6.8"/><path d="m16 16 4.4 4.4M10.8 7.5v3.6l2.4 1.4" stroke-linecap="round"/></svg> Check this message <span aria-hidden="true">→</span>`;
  }
}

function report() {
  if (!current) return "";
  const { result } = current;
  const aiSection = (result.ai_explanation && result.ai_explanation.available && result.ai_explanation.explanation)
    ? `\n\nAI Safety Explanation (Gemini)\n${result.ai_explanation.explanation}`
    : "";
  return `TRUSTLENS SAFETY REPORT\nGenerated: ${new Date().toLocaleString()}\n\nRisk score: ${result.risk_score}/100 — ${result.risk_label}\nAssessment: ${result.classification}\nConfidence: ${Math.round(result.confidence * 100)}% (${result.uncertainty})\n\nSummary\n${result.summary}${aiSection}\n\nEvidence\n${result.findings.map(f => `- ${f.title}: “${f.evidence}” — ${f.explanation}`).join("\n") || "- No specific evidence found."}\n\nWhat to do\n${result.actions.do.map(x => `- ${x}`).join("\n")}\n\nWhat not to do\n${result.actions.dont.map(x => `- ${x}`).join("\n")}\n\nTrusted path\n${result.actions.verify.map(x => `- ${x}`).join("\n")}\n\nNote\n${result.scoring_note}\nTrustLens provides decision support, not an absolute guarantee of safety.`;
}

el("analyzeBtn").addEventListener("click", analyze);

el("copyBtn").addEventListener("click", async () => {
  if (!current) return;
  try {
    await navigator.clipboard.writeText(report());
    toast("Safety report copied to clipboard!");
    const btn = el("copyBtn");
    const orig = btn.innerHTML;
    btn.innerHTML = `✓ Copied!`;
    setTimeout(() => btn.innerHTML = orig, 1800);
  } catch {
    el("error").textContent = "Your browser did not allow clipboard copying.";
  }
});

el("downloadBtn").addEventListener("click", () => {
  if (!current) return;
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([report()], { type: "text/plain" }));
  a.download = "trustlens-safety-report.txt";
  a.click();
  URL.revokeObjectURL(a.href);
  toast("Report download started");
});

function renderHistory() {
  el("historyList").innerHTML = history.length ? history.map(h => `<div class="history-item"><b>${escapeText(h.classification)}</b><span>${escapeText(h.label)} · ${escapeText(h.time)}</span><span class="history-score">${h.score}/100</span></div>`).join("") : `<p class="history-empty">No analyses yet. Results are kept only in this browser tab and never include message text.</p>`;
}

el("clearHistory").addEventListener("click", () => {
  history = [];
  renderHistory();
  toast("Session history cleared");
});

el("samples").innerHTML = samples.map((s, i) => `
  <button class="sample" data-sample="${i}">
    <span class="sample-type">${escapeText(s.type)}</span>
    <h3>${escapeText(s.title)}</h3>
    <p>${escapeText(s.message)}</p>
  </button>
`).join("");

document.querySelectorAll("[data-sample]").forEach(b => {
  b.addEventListener("click", () => {
    const s = samples[Number(b.dataset.sample)];
    message.value = s.message;
    message.dispatchEvent(new Event("input"));
    setContext(s.context);
    document.getElementById("analyze").scrollIntoView({ behavior: "smooth", block: "start" });
    message.focus();
    toast(`Loaded sample: ${s.title}`);
  });
});
