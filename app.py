#!/usr/bin/env python3
"""Flask web app — HASP Downlink Decoder control panel.

Usage:
    python app.py          → opens http://localhost:5000 automatically
"""

from __future__ import annotations

from flask import Flask, jsonify, render_template, request

from constants import CSV_HEADER
from decoder import decode_bytes, decode_text

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html", csv_header=CSV_HEADER)


@app.route("/decode", methods=["POST"])
def decode():
    if "file" in request.files:
        rows, decoded, ignored = decode_bytes(request.files["file"].read())
    else:
        text = (request.get_json(silent=True) or {}).get("text", "")
        rows, decoded, ignored = decode_text(text)

    for row in rows:
        row["crc_ok"] = bool(row["crc_ok"])
        row["frame_ok"] = bool(row["frame_ok"])

    return jsonify(packets=rows, decoded=decoded, ignored=ignored)


if __name__ == "__main__":
    import threading
    import webbrowser

    threading.Timer(0.6, lambda: webbrowser.open("http://localhost:5000")).start()
    app.run(debug=False, port=5000)
