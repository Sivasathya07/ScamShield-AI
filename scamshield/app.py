from flask import Flask, request, jsonify, render_template
from detector import analyze
app = Flask(__name__)

@app.get("/")
def home():
    return render_template("index.html")

@app.post("/api/analyze")
def api():
    return jsonify(analyze((request.get_json(silent=True) or {}).get("text", "")))

if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True, port=5000)
