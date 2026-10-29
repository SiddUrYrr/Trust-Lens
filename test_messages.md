# TrustLens — Test Messages Cheatsheet

Paste these into the analyzer. Select the **Context** tab mentioned before clicking Analyze.

---

## 🔴 HIGH RISK — Should flag as scam

### 1. OTP Scam (Classic)
**Context:** `Account Security`
```
Dear customer, your SBI account KYC is expiring. Share your OTP immediately to avoid account being blocked. Call our helpline now.
```
**Expect:** High Risk · account-security or payment scam · OTP requested + Threat of loss

---

### 2. UPI PIN Fraud
**Context:** `UPI / Payment`
```
I am from QuickPay customer support. To receive your cashback of Rs 5000, please enter your UPI PIN when the collect request appears. This is mandatory to process your refund.
```
**Expect:** High Risk · payment scam · UPI PIN requested + Collect request

---

### 3. KYC Phishing Link
**Context:** `Account Security`
```
HDFC Bank Alert: Your account has been put on hold due to incomplete KYC verification. Update immediately at https://hdfc-kyc-update.example/verify or your account will be suspended within 24 hours.
```
**Expect:** High Risk · phishing · Suspicious link + KYC + Threat

---

### 4. Job Registration Fee
**Context:** `Job / Recruitment`
```
Work from home opportunity! Earn Rs 5000 per day — no experience required, instant joining guaranteed. Pay Rs 299 registration fee today only to activate your account and start earning.
```
**Expect:** High Risk · possible job fraud · Unrealistic job + Advance fee + Urgency

---

### 5. Fake Customer Care — Credential Grab
**Context:** `Account Security`
```
This is Amazon customer care. We detected a failed login attempt on your account. Please confirm your password and card number to secure your account immediately.
```
**Expect:** High Risk · account scam · Credentials requested + Impersonation

---

### 6. Emergency Money Request
**Context:** `General`
```
Hi, this is Rohan's colleague from office. He met with an accident near Pune and is in hospital. He needs Rs 15000 urgently for the deposit. Please send money to this number, he will return it tomorrow.
```
**Expect:** High Risk · Emergency money request + Urgency

---

### 7. Police / Authority Impersonation
**Context:** `General`
```
This is Delhi Cyber Crime Branch. Your mobile number and IP address have been linked to illegal online transactions. To avoid arrest and legal action, call 9876543210 immediately and pay the settlement fee of Rs 25000.
```
**Expect:** High Risk · suspicious · Impersonation + Payment instruction

---

### 8. Hinglish OTP Scam
**Context:** `Account Security`
```
Aapka Paytm account band hone wala hai. Abhi apna OTP batao is number par call karke: 9988776655. Turant karo warna account permanently close ho jayega.
```
**Expect:** High Risk · OTP requested (Hinglish) + Account-blocking threat + Pressure

---

### 9. Hinglish Job Fee
**Context:** `Job / Recruitment`
```
Ghar se kaam karo! Rs 8000 per day ki guaranteed income. Koi experience nahi chahiye. Aaj hi registration fee Rs 499 bhejo aur turant joining letter paao.
```
**Expect:** High Risk · Hinglish fee + Hinglish pressure + Job promise

---

### 10. UPI Collect Request Scam
**Context:** `UPI / Payment`
```
Congratulations! You have won Rs 10000 from our lucky draw. To receive your prize, tap approve on the UPI collect request we just sent. Accept the collect request within 10 minutes or it will expire.
```
**Expect:** High Risk · UPI collect request + Urgency

---

### 11. Phishing — IP Address Link
**Context:** `Phishing Link`
```
Your Jio SIM KYC is pending. Complete verification at http://192.168.1.105/jio-kyc/verify to avoid service interruption. Do it within 2 hours.
```
**Expect:** High Risk · Suspicious link (IP address) + KYC + Threat

---

### 12. Credential Phishing with Suspicious Domain
**Context:** `Phishing Link`
```
IRCTC Security Alert: Unauthorized login detected on your account. Verify your login credentials and card number at https://irctc-secure-login.xyz/confirm before your account is deactivated.
```
**Expect:** High Risk · Suspicious link (.xyz) + Credentials requested + Threat

---

### 13. Crypto / Investment Scam
**Context:** `General`
```
Earn 10x returns on your investment in 30 days! Join our exclusive crypto trading group. Send Rs 5000 to activate your trading account. Guaranteed 50% monthly profit. Limited seats — act now!
```
**Expect:** High Risk · Payment instruction + Urgency

---

### 14. Advance Fee — Income Tax Refund
**Context:** `Phishing Link`
```
Income Tax Department: Your refund of Rs 18450 is on hold. Click https://incometax-refund-claim.example/verify and pay the processing fee of Rs 199 to release your refund immediately.
```
**Expect:** High Risk · Suspicious link + Payment fee + Impersonation

---

### 15. Multi-layered Scam (All Signals Combined)
**Context:** `UPI / Payment`
```
URGENT: Dear customer, your bank account will be blocked within 1 hour due to KYC pending. Share your OTP and UPI PIN to our support team immediately at https://bank-kyc-verify.example/secure. Last warning — act now to avoid penalty.
```
**Expect:** Maximum risk · All groups triggered — OTP + UPI PIN + KYC + Suspicious link + Urgency + Threat

---

## 🟡 CAUTION — Partial signals

### 16. Urgency Only (No Payment/Secret)
**Context:** `General`
```
URGENT: Please respond to this message immediately. The project deadline has been moved to today only. Act now — last warning from the management team.
```
**Expect:** Caution · Pressure/urgency only — low score, inconclusive

---

### 17. KYC Mention Without Action Request
**Context:** `Account Security`
```
Dear customer, your KYC update is pending. Please visit your nearest branch with original documents to complete KYC verification at your convenience.
```
**Expect:** Caution / Inconclusive · KYC only — no secret or link requested

---

### 18. Job Offer Without Fee (Suspicious but Not Confirmed)
**Context:** `Job / Recruitment`
```
Exciting opportunity! Earn Rs 2000 per day working from home. No experience needed. Guaranteed income. WhatsApp us for more details.
```
**Expect:** Caution · Unrealistic job promise, but no fee yet

---

### 19. Impersonation + Urgency, No Secret Requested
**Context:** `Account Security`
```
Customer care team calling. Your account shows unusual activity. Please call back on our helpline number urgently to verify your identity.
```
**Expect:** Caution · Impersonation + Urgency — moderate score

---

### 20. Hinglish Pressure Only
**Context:** `General`
```
Jaldi karo! Abhi reply karo warna aaj hi yeh offer khatam ho jayega. Turant batao.
```
**Expect:** Low / Inconclusive · Hinglish pressure only, no specific scam trigger

---

## 🟢 SAFE — Should show No strong signals / Inconclusive

### 21. Legitimate OTP Message
**Context:** `Account Security`
```
Your OTP for login to Google account is 482736. Valid for 10 minutes. Do NOT share this OTP with anyone, including company employees.
```
**Expect:** No strong signals — OTP is being delivered, not requested

---

### 22. Real Bank Debit Alert
**Context:** `UPI / Payment`
```
Rs 1,250 debited from your HDFC Bank account ending 4321 on 28 Oct at Amazon. Available balance: Rs 24,680. If not done by you, call 1800-XXX-XXXX.
```
**Expect:** Inconclusive / Safe — standard transaction alert

---

### 23. Legitimate UPI Credit
**Context:** `UPI / Payment`
```
Rs 5000 received in your account via UPI from Rahul Sharma. UPI Ref: UPI20231115001. Thank you for using PhonePe.
```
**Expect:** Safe — no suspicious patterns

---

### 24. Normal Delivery Update
**Context:** `General`
```
Your Flipkart order #ORD9876543 has been shipped and is out for delivery today. Expected by 6 PM. No action required.
```
**Expect:** Safe · Link present (if any) — no scam signals

---

### 25. Ambiguous — Discuss Payment
**Context:** `General`
```
Hi, are you free for a call this evening? I wanted to discuss the payment for the project. Let me know when you are available.
```
**Expect:** Inconclusive — no concrete evidence, normal language

---

### 26. Legitimate Loan EMI Reminder
**Context:** `UPI / Payment`
```
Reminder: Your HDFC Bank home loan EMI of Rs 18,500 is due on 5th November. Please ensure sufficient balance in your account. No action needed if auto-debit is set up.
```
**Expect:** Safe — no suspicious request

---

### 27. Real Appointment Reminder
**Context:** `General`
```
Your appointment at Apollo Hospitals is confirmed for 30 Nov at 10:30 AM with Dr. Sharma. Please bring your Aadhaar card and previous reports.
```
**Expect:** Safe · Inconclusive

---

### 28. Normal Friend Message About Emergency (Verified)
**Context:** `General`
```
Hey, hope you are doing well. My father was admitted to hospital yesterday. Thankfully he is stable now. Will be out of office for a few days.
```
**Expect:** Safe · hospital mentioned but no money request pattern

---

## 🔗 LINK TESTS — For URL inspection feature

### 29. Suspicious Subdomain Link
**Context:** `Phishing Link`
```
Verify your Aadhaar-linked bank account at https://secure.verify.kyc.update.example/login before the deadline.
```
**Expect:** Multiple subdomains flagged + verification wording

---

### 30. Rare TLD Phishing
**Context:** `Phishing Link`
```
Your PNB account is locked. Unlock it at https://pnb-banking-secure.click/unlock within 1 hour to avoid permanent closure.
```
**Expect:** Suspicious link (.click TLD) + Threat

---

### 31. IP Address Link
**Context:** `Phishing Link`
```
SBI NetBanking: Login required. Access your account at http://103.45.67.89/sbi/login to complete verification.
```
**Expect:** IP address URL flagged + impersonation

---

### 32. Safe .example Demo Link (Non-suspicious)
**Context:** `Phishing Link`
```
Check out our product demo at https://demo.example and let us know your feedback. No login required.
```
**Expect:** Link present (low) · reserved .example domain noted, no lure terms

---

---

> **Tip:** Mix and match — try the same message with different **context tabs** to see how the score changes. For example, message #17 (KYC) scores higher under `Account Security` than `General`.
