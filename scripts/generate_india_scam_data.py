"""Generate synthetic India-first scam and ham SMS/message data for TrustLens training.

All examples are fictional. No real phone numbers, URLs, or personal details are used.
Label: 1 = scam/spam, 0 = ham (safe/legitimate).
"""
from __future__ import annotations

import csv
import itertools
import random
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT_PATH = ROOT / "data" / "india_scam_synthetic.csv"

random.seed(2024)

# ---------------------------------------------------------------------------
# SCAM TEMPLATES  (label=1)
# ---------------------------------------------------------------------------

OTP_SCAMS = [
    "Dear customer, your {bank} account KYC is expiring. Share your OTP {otp} immediately to keep it active.",
    "Your {bank} account will be blocked in 24 hours. Call us and share the OTP sent to your registered mobile.",
    "Congratulations! You won Rs {amount}. To claim, share the OTP received on your mobile with our agent.",
    "This is {bank} customer care. Your account shows suspicious activity. Verify by sharing your OTP now.",
    "Hi, I'm calling from {bank} fraud team. Please share the OTP just sent to stop unauthorized access.",
    "ALERT: Someone tried to login to your account. Reply with OTP {otp} to block them immediately.",
    "Your one-time password is {otp}. Share this with our support team to complete KYC verification.",
    "Dear valued customer, share your OTP to receive your pending cashback of Rs {amount} from {bank}.",
    "Final warning: your {bank} account will be suspended. Please share OTP to verify your identity.",
    "To activate UPI on {bank}, share the OTP received on {phone}. Do not delay or service will stop.",
    "Apna OTP batao jaldi, warna aapka account band ho jayega. {bank} customer care.",
    "OTP share karo aur Rs {amount} ka cashback paao turant apne account mein.",
    "Aapka {bank} account suspend hone wala hai. Abhi OTP send karo is number par.",
    "Your OTP for fund transfer is {otp}. Please share with our verification team to confirm receipt.",
    "URGENT: Share OTP {otp} to reverse the wrong debit of Rs {amount} from your account.",
]

UPI_PIN_SCAMS = [
    "To receive Rs {amount} from {bank} refund, please enter your UPI PIN when prompted.",
    "I am sending you Rs {amount} via UPI. Please enter your PIN to accept the payment.",
    "Your UPI cashback of Rs {amount} is ready. Tap approve and enter your UPI PIN to receive.",
    "Dear user, please enter UPI PIN to claim your prize of Rs {amount}. Offer expires today.",
    "QuickPay support: approve the collect request and enter your UPI PIN to get your refund.",
    "Aapka UPI PIN enter karo aur Rs {amount} seedha account mein paao. {bank} ki taraf se.",
    "Enter UPI PIN to receive Rs {amount} lottery winnings. Government initiative for citizens.",
    "To complete KYC via UPI, enter your PIN in the {bank} app. This is mandatory.",
    "Refund of Rs {amount} initiated. Accept collect request and enter UPI PIN to process.",
    "UPI PIN dalke apna Rs {amount} ka reward claim karo. Aaj ka offer, kal nahin milega.",
]

JOB_SCAMS = [
    "Work from home! Earn Rs {amount} per day. No experience needed. Pay Rs {fee} registration fee to join now.",
    "Exciting job offer: data entry from home. Salary Rs {amount}/month. Registration fee Rs {fee} only. Limited seats!",
    "Part time job available. Earn Rs {amount} per hour. Instant joining. Pay Rs {fee} processing fee today.",
    "Congratulations! You are selected for work from home position. Salary Rs {amount}/day. Pay security deposit Rs {fee}.",
    "Earn Rs {amount} weekly from home by completing simple tasks. Register now with Rs {fee} activation fee.",
    "HIRING: Online jobs for students and housewives. Earn Rs {amount}/day guaranteed. Pay Rs {fee} to activate account.",
    "Government job vacancy: Rs {amount} per month. No exam, direct selection. Pay Rs {fee} application fee now.",
    "Amazon/Flipkart delivery partner program. Earn Rs {amount} daily. Training fee Rs {fee}. Apply today.",
    "BPO work from home. Rs {amount} weekly. Immediate joining. Pay Rs {fee} registration and get kit.",
    "Ek din mein Rs {amount} kamao ghar se. Koi experience nahi chahiye. Registration fee sirf Rs {fee}.",
    "Salary Rs {amount} per month guaranteed. No target, no boss. Just pay Rs {fee} joining fee.",
    "Online typing jobs: earn Rs {amount} per hour. Pay Rs {fee} security deposit, refundable after 3 months.",
]

PHISHING_LINK_SCAMS = [
    "Your SBI account is on hold. Update KYC at http://sbi-kyc-verify.example/update to avoid suspension.",
    "HDFC Bank alert: suspicious login detected. Verify identity at https://hdfc-secure.example/login immediately.",
    "Your Paytm wallet is blocked. Click https://paytm-kyc.example/verify to restore access within 2 hours.",
    "IRCTC account suspended. Login and update details at http://irctc-verify.example/account now.",
    "Aadhaar link mandatory for UPI. Update at https://upi-aadhaar-link.example/verify before deadline.",
    "Delivery failed for your order. Update address at http://courier-verify.example/redeliver or parcel returns.",
    "Your electricity connection will be cut tonight. Pay overdue at http://bescom-pay.example/bill now.",
    "Income tax refund of Rs {amount} is pending. Claim at https://incometax-refund.example/claim today.",
    "Prize winning SMS: you won Rs {amount}. Claim at http://prize-claim.example/win. Offer valid 24hrs.",
    "GPay lucky draw winner! Collect Rs {amount} at https://gpay-reward.example/claim. KYC needed.",
    "Netflix account suspended. Renew at https://netflix-renew.example/india or lose your data.",
    "Bank loan pre-approved Rs {amount}. Apply at http://bank-loan-offer.example/apply. Limited offer.",
    "COVID relief fund Rs {amount} available. Register at http://pm-relief.example/apply with Aadhaar.",
    "Jio SIM KYC pending. Submit at https://jio-kyc.example/update before service interruption.",
    "PAN card linking deadline. Link PAN at https://pan-link.example/aadhaar or face account freeze.",
]

IMPERSONATION_SCAMS = [
    "This is police cyber crime branch. Your IP address was used for illegal activity. Call {phone} immediately.",
    "CBI officer speaking. You are under investigation for money laundering. Pay Rs {amount} to avoid arrest.",
    "I am from RBI. Your account shows illegal transactions. Cooperate or face legal action. Call now.",
    "Income Tax Department: we found discrepancy in your returns. Pay Rs {amount} fine or face arrest.",
    "Calling from Delhi High Court. A case is filed against you. Settle for Rs {amount} to avoid summons.",
    "This is your bank manager. Your FD is maturing today. Share OTP to reinvest and get bonus interest.",
    "Amazon customer care: refund of Rs {amount} failed. Share bank OTP to process it to your account.",
    "Truecaller verified: TRAI officer calling. Your SIM will be blocked in 2 hours unless you cooperate.",
    "PM Modi's office: you are selected for free laptop scheme. Pay Rs {fee} delivery charge only.",
    "ED enforcement directorate: your account linked to hawala. Pay Rs {amount} or face arrest today.",
]

EMERGENCY_SCAMS = [
    "Hi, this is your son's friend. He had an accident and is in hospital. Please send Rs {amount} urgently.",
    "Mummy, it's me. I lost my phone. Send Rs {amount} to this number, will explain later. Very urgent.",
    "Your relative is stranded at airport. Needs Rs {amount} for emergency. Please transfer immediately.",
    "Hi aunty/uncle, I am in jail. Please send Rs {amount} for bail. Don't tell parents. Very urgent.",
    "Emergency: my wallet stolen in metro. Need Rs {amount} for auto/hotel. Will return tomorrow.",
    "Your friend met with accident near {city}. Hospital needs Rs {amount} deposit. Send now please.",
]

HINGLISH_SCAMS = [
    "Aapka {bank} account band hone wala hai. Abhi apna OTP bataiye warna service stop ho jayegi.",
    "Tumhara account turant block ho jayega. OTP bhejo is number par: {phone}.",
    "Rs {amount} ka cashback aapke liye ready hai. UPI PIN enter karo aur paisa paao.",
    "Aaj hi apply karo, ghar se kaam karo, Rs {amount} daily income guaranteed. Rs {fee} registration fee.",
    "Tumhara SIM band ho jayega agar aaj KYC update nahi kiya. Yahan click karo: http://sim-kyc.example/update",
    "Jaldi karo! Sirf aaj ke liye Rs {amount} ka offer. OTP share karo aur claim karo.",
    "Police case darj hoga agar aaj payment nahi ki. Rs {amount} bhejna padega abhi.",
    "Aapka loan approved hua Rs {amount} ka. Processing fee Rs {fee} bhejna hoga pehle.",
    "Lucky winner! Rs {amount} jeetein! Abhi register karo: http://lucky-win.example/claim",
    "Your UPI PIN share karo receive karne ke liye Rs {amount}. {bank} ki taraf se offer.",
]

CRYPTO_SCAMS = [
    "Earn 10x returns on Bitcoin investment. Join our exclusive crypto trading group. Min investment Rs {amount}.",
    "Guaranteed 50% monthly returns on crypto. Limited spots. Pay Rs {amount} to join our expert group.",
    "Celebrity-endorsed crypto platform. Invest Rs {amount} and earn Rs {amount2} in 30 days guaranteed.",
    "WazirX insider tip: this coin will 100x. Buy now through our link before price rises.",
    "Crypto airdrop! Claim free Bitcoin worth Rs {amount}. Just pay Rs {fee} gas fee to wallet.",
]

# ---------------------------------------------------------------------------
# HAM TEMPLATES  (label=0)
# ---------------------------------------------------------------------------

HAM_BANK = [
    "Your {bank} account has been credited with Rs {amount} on {date}. Available balance: Rs {balance}.",
    "ATM transaction of Rs {amount} done at {bank} ATM on {date}. If not done by you, call {phone}.",
    "Your EMI of Rs {amount} for loan {loan_id} has been debited on {date}.",
    "OTP for your {bank} transaction is {otp}. Valid for 10 minutes. Do NOT share with anyone.",
    "Your {bank} credit card statement for {month} is ready. Total due: Rs {amount}. Pay by {date}.",
    "Debit alert: Rs {amount} debited from account ending {acct} on {date} at {merchant}.",
    "Your {bank} fixed deposit of Rs {amount} has matured. Please visit branch or login to reinvest.",
    "Cheque no {cheque} for Rs {amount} has been cleared from your {bank} account.",
    "Your {bank} account password was changed successfully. If not done by you, call our helpline.",
    "Reminder: your {bank} credit card payment of Rs {amount} is due on {date}. Pay to avoid charges.",
]

HAM_UPI = [
    "Rs {amount} received in your account via UPI from {name}. UPI Ref: {ref}.",
    "You paid Rs {amount} to {merchant} via UPI on {date}. UPI Ref: {ref}.",
    "UPI collect request of Rs {amount} from {name} declined as per your instruction.",
    "Your UPI ID {upi_id} is now linked to your {bank} account successfully.",
    "Payment of Rs {amount} to {merchant} failed. Amount not debited. Retry after some time.",
]

HAM_OTP_LEGIT = [
    "Your OTP for login to {service} is {otp}. Valid for 5 minutes. Do not share with anyone.",
    "{otp} is your verification code for {service}. Never share this OTP with anyone including company staff.",
    "Use OTP {otp} to complete your {service} registration. This OTP is valid for 15 minutes.",
    "Your {service} OTP: {otp}. If you did not request this, ignore this message.",
]

HAM_DELIVERY = [
    "Your {merchant} order #{order_id} has been shipped. Expected delivery: {date}. Track: {merchant}.com/track",
    "Out for delivery: your {merchant} order #{order_id}. Delivery by {time} today.",
    "Your {merchant} order #{order_id} delivered successfully at {date}. Rate your experience.",
    "Delivery attempt failed for order #{order_id}. Will retry tomorrow. No action needed.",
]

HAM_GENERAL = [
    "Hi, are you free for a call this evening? Need to discuss the weekend plan.",
    "Meeting rescheduled to 4 PM tomorrow. Please update your calendar.",
    "Reminder: team lunch at 1 PM today. Restaurant confirmed.",
    "Your appointment at the clinic is confirmed for {date} at {time}.",
    "Library books due for return by {date}. Please renew online to avoid fine.",
    "Society maintenance for {month} is Rs {amount}. Please pay by {date}.",
    "Happy birthday! Wishing you a wonderful year ahead.",
    "The result for your application has been declared. Check the official website.",
    "School fee reminder: Rs {amount} due by {date}. Pay online or at the counter.",
    "Traffic update: avoid MG Road due to waterlogging. Take alternate route.",
    "Your insurance premium of Rs {amount} is due on {date}. Pay to continue coverage.",
    "PF withdrawal request processed. Amount Rs {amount} credited in 3-5 working days.",
    "Your passport is ready for collection at {city} passport office. Bring original documents.",
    "COVID vaccination slot booked for {date} at {hospital}. Bring Aadhaar for verification.",
    "Swiggy order from {restaurant} is being prepared. Estimated delivery: {time} mins.",
    "Your Zomato order has been picked up by the delivery partner. ETA: {time} mins.",
    "Uber ride confirmed. {name} is your driver. Vehicle: {vehicle}. OTP: {otp} (share with driver only).",
    "Ola cab arrives in {time} mins. Driver: {name}. Share trip: only with people you trust.",
    "Your electricity bill for {month} is Rs {amount}. Due date: {date}. Pay at {merchant} or online.",
    "Gas cylinder booking confirmed. Delivery on {date}. Booking no: {ref}.",
]

# ---------------------------------------------------------------------------
# Fillers for template placeholders
# ---------------------------------------------------------------------------
BANKS = ["SBI", "HDFC", "ICICI", "Axis", "Kotak", "PNB", "BOI", "Canara", "Union Bank", "IDBI"]
AMOUNTS = [199, 299, 499, 999, 1499, 1999, 2999, 4999, 9999, 14999, 24999, 49999, 99999, 5000, 10000]
FEES = [99, 199, 299, 499, 799, 999]
PHONES = ["9876543210", "8765432109", "7654321098", "9988776655", "8899001122"]
OTPS = ["482736", "193847", "562910", "837462", "019283"]
DATES = ["15 Nov", "20 Nov", "30 Nov", "5 Dec", "10 Dec", "31 Oct"]
TIMES = ["2 PM", "4 PM", "6 PM", "10 AM", "11:30 AM"]
MONTHS = ["October", "November", "September", "December"]
NAMES = ["Rahul", "Priya", "Amit", "Sunita", "Rohan", "Kavya", "Vijay", "Meena"]
MERCHANTS = ["Amazon", "Flipkart", "Myntra", "Swiggy", "Zomato", "BigBasket", "Nykaa"]
RESTAURANTS = ["Domino's", "KFC", "McDonald's", "Subway", "Pizza Hut", "Biryani House"]
REFS = ["UPI23456789", "UPI98765432", "TXN20231115", "PAY2024001"]
SERVICES = ["Google", "Paytm", "PhonePe", "IRCTC", "DigiLocker", "Aadhaar", "MobiKwik"]
CITIES = ["Delhi", "Mumbai", "Bangalore", "Chennai", "Hyderabad", "Kolkata"]
HOSPITALS = ["Apollo", "Fortis", "AIIMS", "Manipal", "Max", "Narayana"]
VEHICLES = ["Swift DZire", "Honda Amaze", "Maruti Alto", "Hyundai i20"]
LOAN_IDS = ["LN20231001", "LN20231002", "LN20231003"]
CHEQUES = ["123456", "234567", "345678"]
UPI_IDS = ["user@paytm", "user@ybl", "user@okaxis", "user@upi"]
ACCTS = ["1234", "5678", "9012", "3456"]
BALANCES = [15420, 28990, 54321, 102345, 8765]
AMOUNT2_MULT = [2, 3, 5, 10]
ORDER_IDS = ["ORD12345", "ORD98765", "ORD56789", "ORD11111"]


def pick(lst):
    return random.choice(lst)


def fill(template: str) -> str:
    amount = pick(AMOUNTS)
    return (template
            .replace("{bank}", pick(BANKS))
            .replace("{amount}", str(amount))
            .replace("{amount2}", str(amount * pick(AMOUNT2_MULT)))
            .replace("{fee}", str(pick(FEES)))
            .replace("{phone}", pick(PHONES))
            .replace("{otp}", pick(OTPS))
            .replace("{date}", pick(DATES))
            .replace("{time}", pick(TIMES))
            .replace("{month}", pick(MONTHS))
            .replace("{name}", pick(NAMES))
            .replace("{merchant}", pick(MERCHANTS))
            .replace("{restaurant}", pick(RESTAURANTS))
            .replace("{ref}", pick(REFS))
            .replace("{service}", pick(SERVICES))
            .replace("{city}", pick(CITIES))
            .replace("{hospital}", pick(HOSPITALS))
            .replace("{vehicle}", pick(VEHICLES))
            .replace("{loan_id}", pick(LOAN_IDS))
            .replace("{cheque}", pick(CHEQUES))
            .replace("{upi_id}", pick(UPI_IDS))
            .replace("{acct}", pick(ACCTS))
            .replace("{balance}", str(pick(BALANCES)))
            .replace("{order_id}", pick(ORDER_IDS))
            )


def expand(templates: list[str], n: int, label: int) -> list[dict]:
    rows = []
    cycle = itertools.cycle(templates)
    for _ in range(n):
        rows.append({"sms": fill(next(cycle)), "label": label})
    # Shuffle within group
    random.shuffle(rows)
    return rows


def main() -> None:
    rows: list[dict] = []

    # --- SCAM (label=1) ---
    rows += expand(OTP_SCAMS, 200, 1)
    rows += expand(UPI_PIN_SCAMS, 150, 1)
    rows += expand(JOB_SCAMS, 180, 1)
    rows += expand(PHISHING_LINK_SCAMS, 200, 1)
    rows += expand(IMPERSONATION_SCAMS, 150, 1)
    rows += expand(EMERGENCY_SCAMS, 100, 1)
    rows += expand(HINGLISH_SCAMS, 150, 1)
    rows += expand(CRYPTO_SCAMS, 80, 1)

    # --- HAM (label=0) ---
    rows += expand(HAM_BANK, 300, 0)
    rows += expand(HAM_UPI, 200, 0)
    rows += expand(HAM_OTP_LEGIT, 150, 0)
    rows += expand(HAM_DELIVERY, 200, 0)
    rows += expand(HAM_GENERAL, 300, 0)

    random.shuffle(rows)

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with OUT_PATH.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["sms", "label"])
        writer.writeheader()
        writer.writerows(rows)

    spam = sum(1 for r in rows if r["label"] == 1)
    ham = len(rows) - spam
    print(f"Generated {len(rows)} rows -> spam={spam}, ham={ham}")
    print(f"Saved to {OUT_PATH}")


if __name__ == "__main__":
    main()
