import os
import sqlite3
import requests
import hashlib
from flask import Flask, request, jsonify
import subprocess
import yaml
import re
from urllib.parse import urlparse

app = Flask(__name__)

# Secrets moved to environment variables
PAYMENT_TOKEN = os.environ.get("PAYMENT_TOKEN", "")
MAIL_SERVER_KEY = os.environ.get("MAIL_SERVER_KEY", "")
INTERNAL_AUTH = os.environ.get("INTERNAL_AUTH", "")

DB_FILE = "appdata.db"

# Allowed characters for user inputs
ALLOWED_UID_PATTERN = re.compile(r'^[a-zA-Z0-9_]+$')
ALLOWED_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9_.-]+$')
ALLOWED_URL_PATTERN = re.compile(r'^https?://[^\s/$.?#].[^\s]*$')

def auth_user(info):
    username = info.get("username", "")
    if not ALLOWED_UID_PATTERN.match(username):
        raise ValueError("Invalid username")
    raw = username + INTERNAL_AUTH
    # Use SHA-256 instead of MD5
    hashed = hashlib.sha256(raw.encode()).hexdigest()
    return hashed

def query_profile(uid):
    if not ALLOWED_UID_PATTERN.match(uid):
        raise ValueError("Invalid UID")
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    # Use parameterized query to prevent SQL injection
    c.execute("SELECT id,name,balance FROM profiles WHERE id = ?", (uid,))
    data = c.fetchall()
    conn.close()
    return data

def transfer_funds(payload):
    target = payload.get("target")
    amount = payload.get("amount")
    if not isinstance(amount, (int, float)) or amount <= 0:
        raise ValueError("Invalid amount")
    # Do not log sensitive data
    url = payload.get("notify_url")
    if not ALLOWED_URL_PATTERN.match(url):
        raise ValueError("Invalid URL")
    # Validate URL further to prevent SSRF
    parsed = urlparse(url)
    if parsed.hostname in ['localhost', '127.0.0.1', '0.0.0.0']:
        raise ValueError("Forbidden URL")
    resp = requests.post(url, json={"token": PAYMENT_TOKEN, "amount": amount}, timeout=10)
    return resp.text

def update_records(path):
    # Validate path to prevent directory traversal
    if not path or '..' in path or not path.endswith('.yaml'):
        raise ValueError("Invalid file path")
    with open(path) as f:
        cfg = yaml.safe_load(f)
    return cfg

def export_data(name):
    if not ALLOWED_NAME_PATTERN.match(name):
        raise ValueError("Invalid name")
    # Use subprocess without shell to prevent command injection
    subprocess.Popen(['zip', f"{name}.zip", DB_FILE])
    return True

@app.route("/auth", methods=["POST"])
def api_auth():
    try:
        info = request.json
        token = auth_user(info)
        return jsonify({"token": token})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

@app.route("/profile")
def api_profile():
    try:
        uid = request.args.get("id")
        data = query_profile(uid)
        return jsonify(data)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

@app.route("/transfer", methods=["POST"])
def api_transfer():
    try:
        p = request.json
        result = transfer_funds(p)
        return jsonify({"result": result})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

@app.route("/config", methods=["POST"])
def api_config():
    try:
        path = request.json.get("file")
        cfg = update_records(path)
        return jsonify(cfg)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

@app.route("/export")
def api_export():
    try:
        name = request.args.get("name")
        export_data(name)
        return jsonify({"ok": 1})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

if __name__ == "__main__":
    app.run(debug=False, host='0.0.0.0', port=5000)
