import os
import sqlite3
import requests
import hashlib
import hmac
import secrets
import logging
import re
import zipfile
from urllib.parse import urlparse
from flask import Flask, request, jsonify
import yaml

app = Flask(__name__)

# Secrets come from environment with test-only fallbacks (allow-fallbacks).
# Production deployments SHOULD set these environment variables.
PAYMENT_TOKEN = os.getenv("PAYMENT_TOKEN", "tok_test_998877")
MAIL_SERVER_KEY = os.getenv("MAIL_SERVER_KEY", "mail_test_ABCDEFG")
INTERNAL_AUTH = os.getenv("INTERNAL_AUTH", "internal_test_5566")

DB_FILE = os.getenv("DB_FILE", "appdata.db")

# Security configuration
MAX_CONTENT_LENGTH = 10 * 1024            # 10 KB max request body
CONFIG_DIR = os.getenv("CONFIG_DIR", "configs")
NOTIFY_ALLOWLIST = set(x for x in os.getenv("NOTIFY_ALLOWLIST", "").split(",") if x)

# helpers
def _redact_secret(val: str) -> str:
    if not val:
        return val
    return f"{val[:4]}...{val[-4:]}"


def auth_user(info):
    """Generate a signed token using HMAC-SHA256 (not MD5).
    Preserves intended deterministic behavior but uses a secure MAC.
    """
    username = (info or {}).get("username", "")
    key = INTERNAL_AUTH.encode("utf-8")
    dig = hmac.new(key, username.encode("utf-8"), hashlib.sha256).hexdigest()
    return dig


def query_profile(uid):
    if uid is None:
        raise ValueError("uid is required")
    # allow-list numeric IDs only to prevent SQL injection
    if not re.fullmatch(r"\d+", str(uid)):
        return []
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("SELECT id,name,balance FROM profiles WHERE id = ?", (int(uid),))
        return c.fetchall()


def transfer_funds(payload):
    target = payload.get("target")
    amount = payload.get("amount")
    url = payload.get("notify_url")
    # validate basic fields
    if amount is None:
        raise ValueError("amount required")
    if not url:
        raise ValueError("notify_url required")
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("invalid notify_url")
    host = parsed.netloc.split(":")[0]
    # deny-by-default: require NOTIFY_ALLOWLIST to explicitly allow outbound
    if not NOTIFY_ALLOWLIST or host not in NOTIFY_ALLOWLIST:
        raise ValueError("notify_url not allowed")
    logging.info("transfer to %s amount=%s", host, amount)
    payload_json = {"token": PAYMENT_TOKEN, "amount": amount}
    try:
        resp = requests.post(url, json=payload_json, timeout=5, allow_redirects=False)
        resp.raise_for_status()
    except Exception:
        logging.exception("notify failed")
        raise
    return resp.text


def update_records(path):
    if not path:
        raise ValueError("file path required")
    # restrict file access to CONFIG_DIR (prevent path traversal)
    safe_base_candidates = [
        os.path.abspath(CONFIG_DIR),
        os.path.abspath(os.path.join(os.path.dirname(__file__), CONFIG_DIR)),
    ]
    candidate = None
    for base in safe_base_candidates:
        cand = os.path.abspath(os.path.join(base, path))
        if cand.startswith(base + os.sep) and os.path.exists(cand):
            candidate = cand
            break
    if candidate is None:
        # either access denied or file not present
        raise FileNotFoundError("config not found or access denied")
    if os.path.getsize(candidate) > 100 * 1024:
        raise ValueError("file too large")
    with open(candidate, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    # redact secrets from returned config
    def _sanitize(obj):
        if isinstance(obj, dict):
            out = {}
            for k, v in obj.items():
                if re.search(r"(?i)secret|token|password|api(_)?key|internal|system_prompt", k):
                    out[k] = "<REDACTED>"
                else:
                    # redact exact matches to known internal secrets
                    if isinstance(v, str) and v == INTERNAL_AUTH:
                        out[k] = "<REDACTED>"
                    else:
                        out[k] = _sanitize(v)
            return out
        if isinstance(obj, list):
            return [_sanitize(x) for x in obj]
        if isinstance(obj, str):
            if re.search(r"AKIA|AIza|-----BEGIN .*PRIVATE KEY-----|[A-Za-z0-9]{32,}", obj):
                return "<REDACTED>"
            return obj
        return obj
    return _sanitize(cfg)


def export_data(name):
    # allow-list characters for archive name to prevent command injection
    if not name or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", name):
        raise ValueError("invalid export name")
    archive = f"{name}.zip"
    # use Python's zipfile (no shell/exec)
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.write(DB_FILE, arcname=os.path.basename(DB_FILE))
    return os.path.abspath(archive)


@app.route("/auth", methods=["POST"])
def api_auth():
    info = request.json
    return jsonify({"token": auth_user(info)})


@app.route("/profile")
def api_profile():
    uid = request.args.get("id")
    return jsonify(query_profile(uid))


@app.route("/transfer", methods=["POST"])
def api_transfer():
    p = request.json
    return jsonify({"result": transfer_funds(p)})


@app.route("/config", methods=["POST"])
def api_config():
    path = request.json.get("file")
    return jsonify(update_records(path))


@app.route("/export")
def api_export():
    name = request.args.get("name")
    export_data(name)
    return jsonify({"ok": 1})


if __name__ == "__main__":
    # safer defaults: debug off unless explicitly enabled in the environment
    debug = os.getenv("FLASK_DEBUG", "0") == "1"
    app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
    logging.basicConfig(level=logging.INFO)
    app.run(host="0.0.0.0", debug=debug)
