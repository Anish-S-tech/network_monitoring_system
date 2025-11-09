#!/usr/bin/env python3
from flask import Flask, jsonify, request, send_file
from flask_cors import CORS
from utils import load_config, setup_db
from sqlalchemy import select
import os, sqlite3, json

CFG = load_config("config.yaml")
DB_PATH = CFG.get("db_path", "./data/alerts.db")

app = Flask(__name__)
CORS(app)

@app.route("/api/alerts", methods=["GET"])
def get_alerts():
    # simple read from sqlite
    import sqlite3
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT id,timestamp,event_type,src_ip,dst_ip,details,ml_score FROM alerts ORDER BY id DESC LIMIT 500")
    rows = cur.fetchall()
    conn.close()
    out = []
    for r in rows:
        d = {"id": r[0], "timestamp": r[1], "event_type": r[2], "src_ip": r[3], "dst_ip": r[4], "details": json.loads(r[5]) if r[5] else {}, "ml_score": r[6]}
        out.append(d)
    return jsonify(out)

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status":"ok"})

@app.route("/api/logfile", methods=["GET"])
def download_log():
    path = os.path.join(CFG.get("log_dir","./logs"), "agent.log")
    if os.path.exists(path):
        return send_file(path, as_attachment=True)
    return jsonify({"error": "log not found"}), 404

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
