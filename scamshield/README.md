# 🛡️ ScamShield AI
Explainable, multilingual (English / Tamil / Hindi / Tanglish) scam-message detector for SMS, WhatsApp and UPI fraud.

**Hybrid AI:** char n-gram TF-IDF + Logistic Regression (handles code-mixed text and spelling tricks) fused with an
explainable rule engine (OTP/PIN requests, fake links, urgency, threats, upfront fees, digital-arrest scripts).
Every verdict shows *why*, plus a safe action (report at cybercrime.gov.in / 1930).

## Run
```bash
pip install -r requirements.txt
python app.py
```
Then open http://127.0.0.1:5000

API example:
```bash
curl -X POST http://127.0.0.1:5000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"text":"Your bank account will be blocked. Share OTP immediately."}'
```

## Roadmap
Train on a larger labelled dataset, add URL reputation, WhatsApp bot, on-device Android app, and voice-call scam detection.
