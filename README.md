# ScamShield AI

This repository contains a lightweight Flask app that analyzes scam-like messages and explains the risk level with ML and rule-based signals.

## Project structure

- `scamshield/app.py` - Flask app entry point
- `scamshield/detector.py` - scam detection logic
- `scamshield/templates/index.html` - web UI
- `scamshield/requirements.txt` - Python dependencies

## Run locally

```bash
python -m pip install -r requirements.txt
python scamshield/app.py
```

Then open: http://127.0.0.1:5000

## API

```bash
curl -X POST http://127.0.0.1:5000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"text":"Your bank account will be blocked. Share OTP immediately."}'
```

## GitHub-ready notes

- A root `.gitignore` is included to avoid committing virtual environments and editor artifacts.
- The project is ready to initialize as a Git repository and push to GitHub.
