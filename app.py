"""NetShield IDS - Flask server. Run:  python app.py  (as Administrator)"""
from flask import Flask, jsonify, render_template
import detector

app = Flask(__name__)


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
    detector.start_sniffer()
    print("NetShield IDS running -> open http://localhost:5000")
    app.run(host="127.0.0.1", port=5000, debug=False)