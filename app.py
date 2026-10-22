
"""NetShield IDS - Flask server for online demo."""
import os
from flask import Flask, jsonify, render_template
import detector

app = Flask(__name__)

# Disable real packet capture for the online demo by default.
if os.environ.get("ENABLE_SNIFFER", "0") == "1":
    detector.start_sniffer()


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/data")
def data():
    return jsonify(detector.snapshot())


@app.route("/api/simulate/<kind>", methods=["POST"])
def simulate(kind):
    ok = detector.simulate(kind)
    return jsonify({"ok": ok}), (200 if ok else 400)


@app.route("/api/reset", methods=["POST"])
def reset():
    detector.reset()
    return jsonify({"ok": True})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
