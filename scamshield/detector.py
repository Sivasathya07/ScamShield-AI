"""ScamShield AI - hybrid explainable scam detector (rules + ML)."""
import re
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline

SCAM = [
 "Dear customer your SBI account will be blocked today. Update KYC now http://sbi-kyc-update.xyz",
 "Congratulations! You won Rs 25,00,000 lottery. Share OTP to claim prize immediately",
 "Your electricity will be disconnected tonight 9.30pm. Call 98XXXXXX01 officer now to pay pending bill",
 "Urgent: income tax refund of Rs 15,490 approved. Click bit.ly/refund-now to verify bank details",
 "You received Rs 5000 on PhonePe by mistake. Please send back using this link or enter your UPI PIN",
 "Work from home, earn Rs 5000 daily. Pay Rs 999 registration fee on Telegram to start",
 "Your parcel is held at customs. Pay Rs 49 delivery fee at http://india-post-track.top to release",
 "Unga bank account block aagum. Udane KYC update pannunga link click pannunga http://kyc-bank.live",
 "Aapka SIM 24 ghante mein band ho jayega. Abhi Aadhaar verify karein, OTP share karein",
 "Digital arrest notice: CBI officer says your Aadhaar is used in crime. Transfer money to safe account now",
 "Your credit card reward points expire today. Redeem now at http://hdfc-rewards.click enter card number and CVV",
 "Vazhthukkal! Neenga Rs 10 latcham lottery jeichirukinga. OTP anuppunga prize claim panna",
 "Hi I am your relative abroad, send gift customs charges Rs 20000 to this account urgently",
 "Your Amazon order cancelled. Refund pending, click link and enter UPI PIN to receive money",
 "Final warning: electricity bill unpaid, power cut in 2 hours, contact officer on WhatsApp 90XXXXXX11",
]
SAFE = [
 "Your OTP for login is 482913. Do not share it with anyone. - HDFC Bank",
 "Hi, are we still meeting for lunch tomorrow at 1pm?",
 "Your Swiggy order #4412 is out for delivery and will arrive in 15 minutes",
 "Rs 1,200 debited from A/c XX4521 at BigBasket on 12-Oct. Avl bal Rs 18,430. - ICICI Bank",
 "Amma, I reached home safely. Will call you after dinner",
 "Reminder: your appointment with Dr. Kumar is on Friday 4:30 PM at Apollo Clinic",
 "Your electricity bill of Rs 842 for Sept has been paid successfully via TNEB portal. Thank you",
 "Meeting moved to 3pm, link is in the calendar invite. Please confirm",
 "Nalaiku college leave. Assignment submission Monday varai extend pannirukanga",
 "Your Amazon order has been shipped and will arrive by Thursday. Track in the app",
 "Happy birthday! Wishing you a wonderful year ahead. Treat kudu da!",
 "Your monthly statement is ready. Login to the official app to view. We never ask for PIN or OTP.",
 "Class test syllabus shared in the group. Please go through units 3 and 4",
 "Aapka order deliver ho gaya hai. Dhanyavaad for shopping with us",
 "Your train PNR 4521367890 is confirmed. Chennai Egmore to Madurai, 14 Oct, coach S4",
]

# (name, regex, weight, human explanation)
RULES = [
 ("Asks for secret credentials", r"\b(otp|upi pin|cvv|pin|password|card number)\b.*\b(share|send|enter|anuppunga|karein|batao)\b|\b(share|send|enter)\b.*\b(otp|upi pin|cvv|pin|password)\b", 35, "Banks and apps never ask you to share OTP/PIN/CVV."),
 ("Suspicious link", r"https?://\S+\.(xyz|top|click|live|icu|buzz|shop)\b|\bbit\.ly/|\btinyurl\.com/|https?://\d{1,3}(\.\d{1,3}){3}", 25, "Shortened or odd-domain link, a common phishing trick."),
 ("Artificial urgency", r"\b(urgent|immediately|today|tonight|within \d+ ?(hours|hrs)|24 ghante|udane|abhi|final warning|in \d+ hours)\b", 15, "Scammers rush you so you don't think or verify."),
 ("Threat of blocking/arrest", r"\b(blocked?|disconnect(ed)?|suspend(ed)?|digital arrest|cbi|police|legal action|band ho|block aagum|power cut)\b", 20, "Fear-based threat to force quick action."),
 ("Too-good-to-be-true reward", r"\b(lottery|won|prize|congratulations|vazhthukkal|refund|reward points|earn rs ?\d+ ?daily|latcham)\b", 20, "Unexpected prize/refund is a classic bait."),
 ("Asks for money/fees upfront", r"\b(registration fee|processing fee|customs|delivery fee|transfer money|safe account|pay rs ?\d+|send back)\b", 25, "Genuine services do not demand upfront fees via chat."),
 ("Unknown contact request", r"\b(call|contact|whatsapp|telegram)\b.*\b(officer|agent|\d{2}x{3,}\d*|9\d{1}x{4,})", 15, "Moves you to a private channel to avoid detection."),
 ("Official reassurance (safe sign)", r"do not share|never ask for (pin|otp)|avl bal|debited from", -30, "Matches the wording of genuine bank notices."),
]

_model = make_pipeline(
    TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5), lowercase=True, sublinear_tf=True),
    LogisticRegression(C=4, max_iter=1000),
).fit(SCAM + SAFE, [1] * len(SCAM) + [0] * len(SAFE))

ADVICE = {
 "HIGH": "Do NOT click, reply or share anything. Block the sender and report at cybercrime.gov.in or call 1930.",
 "MEDIUM": "Be careful. Verify through the official app/website or the number printed on your card, not this message.",
 "LOW": "Looks normal, but never share OTP/PIN with anyone.",
}

def analyze(text: str) -> dict:
    t = text.strip()
    if not t:
        return {"error": "Empty message"}
    ml = float(_model.predict_proba([t])[0][1]) * 100
    hits, rule_score = [], 0
    for name, rx, w, why in RULES:
        if re.search(rx, t, re.I | re.S):
            hits.append({"signal": name, "why": why, "weight": w})
            rule_score += w
    rule_score = max(0, min(100, rule_score))
    score = round(0.55 * rule_score + 0.45 * ml)
    if rule_score >= 60: score = max(score, 75)   # strong rule evidence overrides weak ML
    score = max(0, min(100, score))
    level = "HIGH" if score >= 65 else "MEDIUM" if score >= 35 else "LOW"
    return {"score": score, "level": level, "ml_score": round(ml), "rule_score": rule_score,
            "signals": hits, "advice": ADVICE[level]}
