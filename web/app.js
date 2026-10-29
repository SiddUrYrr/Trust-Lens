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
let context = "general";
let current = null;
let history = [];
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
  job: "Job / recruitment — offers, salary promises, interview requests, and advance-fee messages.",
  phishing: "Phishing link — links, delivery updates, verification prompts, and login requests.",
  account: "Account security — KYC, OTP, login, account-blocking, and security alert messages.",
  general: "General message — SMS, WhatsApp messages, emails, or anything that does not fit a specific category."
};

function setContext(next) {
  context = next;
  message.placeholder = contextPrompts[next];
  el("contextHint").textContent = contextHints[next];
  document.querySelectorAll("[data-context]").forEach(b => b.classList.toggle("selected", b.dataset.context === next));
  invalidateAnalysis();
}
document.querySelectorAll("[data-context]").forEach(button => button.addEventListener("click", () => setContext(button.dataset.context)));
function invalidateAnalysis() {
  if (!current) return;
  current = null;
  el("result").classList.add("hidden");
  el("emptyResult").classList.remove("hidden");
}
message.addEventListener("input", () => {
  el("charCount").textContent = `${message.value.length.toLocaleString()} / 8,000`;
  invalidateAnalysis();
});
el("clearBtn").addEventListener("click", () => { message.value=""; message.dispatchEvent(new Event("input")); message.focus(); });

function escapeText(text) { const node = document.createElement("span"); node.textContent = text; return node.innerHTML; }
function highlight(text, findings) {
  const ranges = findings.map(f=>({start:f.start,end:f.end})).sort((a,b)=>a.start-b.start || b.end-a.end);
  let html="", pos=0;
  for (const range of ranges) { if (range.start < pos) continue; html += escapeText(text.slice(pos,range.start)); html += `<mark class="evidence-mark">${escapeText(text.slice(range.start,range.end))}</mark>`; pos=range.end; }
  return html + escapeText(text.slice(pos));
}
function list(items, target) { el(target).innerHTML = `<ul>${items.map(x=>`<li>${escapeText(x)}</li>`).join("")}</ul>`; }
function renderLinkChecks(checks) {
  const container = el("linkChecks");
  if (!checks.length) { container.classList.add("hidden"); return; }
  container.classList.remove("hidden");
  container.innerHTML = `<span class="eyebrow">Link inspection</span><h2>Observed URL signals</h2><p>Links are never opened, resolved, or fetched by TrustLens.</p>${checks.map(check => `<div class="link-row"><strong>${escapeText(check.host)}</strong><ul>${check.signals.map(signal => `<li>${escapeText(signal)}</li>`).join("")}</ul></div>`).join("")}`;
}
function display(result, rawMessage) {
  current={result,rawMessage}; el("emptyResult").classList.add("hidden"); el("result").classList.remove("hidden");
  el("riskLabel").textContent=result.risk_label; el("score").textContent=result.risk_score; el("summary").textContent=result.summary; el("classification").textContent=result.classification;
  el("scoringNote").textContent=result.scoring_note; el("confidence").textContent=`${Math.round(result.confidence*100)}%`; el("uncertainty").textContent=result.uncertainty;
  const ml = result.ml_signal || {available:false,label:"Unavailable",note:"No local SMS model signal."};
  el("mlLabel").textContent = ml.available && ml.confidence !== null ? `${ml.label} · ${Math.round(ml.confidence * 100)}%` : ml.label;
  el("mlNote").textContent = ml.note;
  const ai = result.ai_explanation || {available:false};
  const aiCard = el("aiCard");
  if (ai.available && ai.explanation) {
    aiCard.classList.remove("hidden");
    el("aiText").textContent = ai.explanation;
    el("aiNote").textContent = ai.note || "";
  } else {
    aiCard.classList.add("hidden");
  }
  const color=result.risk_score>=65?"#f28a86":result.risk_score>=35?"#f3c970":"#54d7b0"; el("scoreRing").style.borderColor=color;
  el("highlightedMessage").innerHTML=highlight(rawMessage,result.findings); el("findingCount").textContent=`${result.findings.length} finding${result.findings.length===1?"":"s"}`;
  el("findings").innerHTML=result.findings.length ? result.findings.map(f=>`<article class="finding ${f.severity}"><i class="finding-dot"></i><div><strong>${escapeText(f.title)}</strong><p>${escapeText(f.explanation)}</p></div><code>${escapeText(f.evidence)}</code></article>`).join("") : `<p class="history-empty">No specific evidence was found. Treat unexpected messages with normal caution.</p>`;
  renderLinkChecks(result.link_checks || []);
  list(result.actions.do,"doList"); list(result.actions.dont,"dontList"); list(result.actions.verify,"verifyList");
  history.unshift({label:result.risk_label,score:result.risk_score,classification:result.classification,time:new Date().toLocaleTimeString([], {hour:"2-digit",minute:"2-digit"})}); history=history.slice(0,6); renderHistory(); el("result").scrollIntoView({behavior:"smooth",block:"start"});
}
async function analyze() {
  const raw=message.value.trim(); el("error").textContent=""; if(!raw){ el("error").textContent="Enter a message to analyze."; message.focus(); return; }
  const button=el("analyzeBtn"); button.disabled=true; button.innerHTML="Analyzing evidence…";
  try { const res=await fetch("/api/analyze",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({message:raw,context})}); const body=await res.json(); if(!res.ok) throw new Error(body.detail || "Analysis could not be completed."); display(body,raw); }
  catch(err){el("error").textContent=err.message || "Analysis service unavailable. Please try again.";}
  finally {button.disabled=false; button.innerHTML="Analyze safely <span>→</span>";}
}
function report() {
  if(!current) return "";
  const {result,rawMessage}=current;
  const aiSection = (result.ai_explanation && result.ai_explanation.available && result.ai_explanation.explanation)
    ? `\n\nAI Safety Explanation (Gemini)\n${result.ai_explanation.explanation}`
    : "";
  return `TRUSTLENS SAFETY REPORT\nGenerated: ${new Date().toLocaleString()}\n\nRisk score: ${result.risk_score}/100 — ${result.risk_label}\nAssessment: ${result.classification}\nConfidence: ${Math.round(result.confidence*100)}% (${result.uncertainty})\n\nSummary\n${result.summary}${aiSection}\n\nEvidence\n${result.findings.map(f=>`- ${f.title}: “${f.evidence}” — ${f.explanation}`).join("\n") || "- No specific evidence found."}\n\nWhat to do\n${result.actions.do.map(x=>`- ${x}`).join("\n")}\n\nWhat not to do\n${result.actions.dont.map(x=>`- ${x}`).join("\n")}\n\nNote\n${result.scoring_note}\nTrustLens is decision support, not a guarantee of safety.`;
}
el("analyzeBtn").addEventListener("click",analyze);
el("copyBtn").addEventListener("click",async()=>{if(!current)return;try{await navigator.clipboard.writeText(report());el("copyBtn").textContent="Copied";setTimeout(()=>el("copyBtn").textContent="Copy safety report",1400)}catch{el("error").textContent="Your browser did not allow copying."}});
el("downloadBtn").addEventListener("click",()=>{if(!current)return;const a=document.createElement("a");a.href=URL.createObjectURL(new Blob([report()],{type:"text/plain"}));a.download="trustlens-safety-report.txt";a.click();URL.revokeObjectURL(a.href);});
function renderHistory(){el("historyList").innerHTML=history.length?history.map(h=>`<div class="history-item"><b>${escapeText(h.classification)}</b><span>${escapeText(h.label)} · ${escapeText(h.time)}</span><span class="history-score">${h.score}/100</span></div>`).join(""):`<p class="history-empty">No analyses yet. Results are kept only in this browser tab and never include message text.</p>`}
el("clearHistory").addEventListener("click",()=>{history=[];renderHistory()});
el("samples").innerHTML=samples.map((s,i)=>`<button class="sample" data-sample="${i}"><span class="sample-type">${s.type}</span><h3>${s.title}</h3><p>${s.message}</p></button>`).join("");
document.querySelectorAll("[data-sample]").forEach(b=>b.addEventListener("click",()=>{const s=samples[Number(b.dataset.sample)];message.value=s.message;message.dispatchEvent(new Event("input"));setContext(s.context);document.getElementById("analyze").scrollIntoView({behavior:"smooth",block:"start"});message.focus()}));
