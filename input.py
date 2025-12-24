import os
import sqlite3
import requests
import hashlib
from flask import Flask, request, jsonify
import subprocess
import hmac
import secrets
from urllib.parse import urlparse
from pathlib import Path
import logging

app = Flask(__name__)

# SECURITY: Load secrets from environment variables, not hardcoded
PAYMENT_TOKEN = os.environ.get("PAYMENT_TOKEN")
MAIL_SERVER_KEY = os.environ.get("MAIL_SERVER_KEY")
INTERNAL_AUTH_SECRET = os.environ.get("INTERNAL_AUTH_SECRET")

# Validate required secrets are present
if not all([PAYMENT_TOKEN, MAIL_SERVER_KEY, INTERNAL_AUTH_SECRET]):
    raise RuntimeError("Required environment variables not set")

DB_FILE = "appdata.db"
ALLOWED_EXPORT_NAMES = set()  # Allowlist for export names
ALLOWED_CONFIG_PATHS = {"/etc/config.yaml"}  # Allowlist for config paths
ALLOWED_NOTIFY_DOMAINS = {"payment-api.internal.example.com", "notify.internal.example.com"}

# Setup secure logging (no sensitive data)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def auth_user(info):
    """
    Authenticate user with HMAC-SHA256 instead of MD5.
    SECURITY: MD5 is cryptographically broken; using HMAC-SHA256.
    """
    username = info.get("username", "")
    
    # Validate input
    if not isinstance(username, str) or len(username) > 255:
        logger.warning("Invalid username format")
        return None
    
    # Use HMAC-SHA256 with secret from environment
    message = username.encode('utf-8')
    hashed = hmac.new(
        INTERNAL_AUTH_SECRET.encode('utf-8'),
        message,
        hashlib.sha256
    ).hexdigest()
    return hashed


def query_profile(uid):
    """
    Query user profile with parameterized queries to prevent SQL injection.
    SECURITY: Using ? placeholders instead of string concatenation.
    """
    # Validate UID: must be numeric
    if not isinstance(uid, str) or not uid.isdigit():
        logger.warning(f"Invalid UID format: {uid}")
        return []
    
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        # Use parameterized query to prevent SQL injection
        c.execute("SELECT id, name, balance FROM profiles WHERE id = ?", (uid,))
        data = c.fetchall()
        conn.close()
        return data
    except sqlite3.Error as e:
        logger.error(f"Database error: {str(e)[:100]}")
        return []


def transfer_funds(payload):
    """
    Transfer funds with URL validation and no credential leakage.
    SECURITY: Validate notify_url against allowlist; don't log sensitive data.
    """
    target = payload.get("target", "")
    amount = payload.get("amount")
    
    # Validate inputs
    if not isinstance(target, str) or not target.isdigit():
        logger.warning("Invalid target format")
        return {"error": "Invalid target"}
    
    if not isinstance(amount, (int, float)) or amount <= 0 or amount > 1_000_000:
        logger.warning("Invalid amount")
        return {"error": "Invalid amount"}
    
    # Log without sensitive data (amount is non-sensitive in this context)
    logger.info(f"transfer initiated: amount={amount}")
    
    url = payload.get("notify_url", "")
    
    # SECURITY: Validate URL against allowlist to prevent SSRF
    if not url:
        logger.warning("Missing notify_url")
        return {"error": "notify_url required"}
    
    try:
        parsed = urlparse(url)
        if parsed.hostname not in ALLOWED_NOTIFY_DOMAINS:
            logger.warning(f"URL not in allowlist: {parsed.hostname}")
            return {"error": "Invalid notify domain"}
    except Exception as e:
        logger.warning(f"Invalid URL format: {str(e)[:100]}")
        return {"error": "Invalid URL"}
    
    try:
        # Timeout prevents hanging; don't send full token in request
        resp = requests.post(url, json={"amount": amount}, timeout=5, verify=True)
        resp.raise_for_status()
        return {"status": "ok"}
    except requests.RequestException as e:
        logger.error(f"Request failed: {str(e)[:100]}")
        return {"error": "Transfer notification failed"}


def update_records(path):
    """
    Load configuration from file with path validation.
    SECURITY: Restrict to allowlist of safe paths.
    """
    # Validate path is in allowlist
    if path not in ALLOWED_CONFIG_PATHS:
        logger.warning(f"Config path not in allowlist: {path}")
        return {}
    
    try:
        with open(path, 'r') as f:
            cfg = yaml.safe_load(f)
        if not isinstance(cfg, dict):
            logger.warning("Config is not a dict")
            return {}
        return cfg
    except Exception as e:
        logger.error(f"Config load error: {str(e)[:100]}")
        return {}


def export_data(name):
    """
    Export data with filename validation and safe subprocess call.
    SECURITY: Validate name; use list instead of shell=True; no shell injection.
    """
    # Validate name: alphanumeric + underscore only
    if not name or not all(c.isalnum() or c == '_' for c in name):
        logger.warning(f"Invalid export name: {name}")
        return False
    
    if len(name) > 50:
        logger.warning("Export name too long")
        return False
    
    try:
        # SECURITY: Use list format instead of shell=True to prevent command injection
        cmd = ["zip", f"{name}.zip", DB_FILE]
        result = subprocess.run(cmd, capture_output=True, timeout=30, check=False)
        
        if result.returncode != 0:
            logger.error(f"Zip failed: {result.stderr.decode()[:100]}")
            return False
        return True
    except Exception as e:
        logger.error(f"Export error: {str(e)[:100]}")
        return False


@app.route("/auth", methods=["POST"])
def api_auth():
    """Authenticate user and return token."""
    try:
        info = request.get_json(force=True, silent=True)
        if not info:
            return jsonify({"error": "Invalid JSON"}), 400
        
        token = auth_user(info)
        if not token:
            return jsonify({"error": "Invalid credentials"}), 400
        
        return jsonify({"token": token})
    except Exception as e:
        logger.error(f"Auth error: {str(e)[:100]}")
        return jsonify({"error": "Authentication failed"}), 500


@app.route("/profile")
def api_profile():
    """Retrieve user profile by ID."""
    try:
        uid = request.args.get("id", "")
        if not uid:
            return jsonify({"error": "Missing id"}), 400
        
        data = query_profile(uid)
        return jsonify({"profiles": data})
    except Exception as e:
        logger.error(f"Profile error: {str(e)[:100]}")
        return jsonify({"error": "Profile lookup failed"}), 500


@app.route("/transfer", methods=["POST"])
def api_transfer():
    """Transfer funds to recipient."""
    try:
        p = request.get_json(force=True, silent=True)
        if not p:
            return jsonify({"error": "Invalid JSON"}), 400
        
        result = transfer_funds(p)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Transfer error: {str(e)[:100]}")
        return jsonify({"error": "Transfer failed"}), 500


@app.route("/config", methods=["POST"])
def api_config():
    """Update configuration from file."""
    try:
        data = request.get_json(force=True, silent=True)
        if not data:
            return jsonify({"error": "Invalid JSON"}), 400
        
        path = data.get("file", "")
        if not path:
            return jsonify({"error": "Missing file"}), 400
        
        cfg = update_records(path)
        return jsonify({"config": cfg})
    except Exception as e:
        logger.error(f"Config error: {str(e)[:100]}")
        return jsonify({"error": "Config load failed"}), 500


@app.route("/export")
def api_export():
    """Export data to zip file."""
    try:
        name = request.args.get("name", "")
        if not name:
            return jsonify({"error": "Missing name"}), 400
        
        success = export_data(name)
        if not success:
            return jsonify({"error": "Export failed"}), 400
        
        return jsonify({"ok": 1})
    except Exception as e:
        logger.error(f"Export error: {str(e)[:100]}")
        return jsonify({"error": "Export failed"}), 500


if __name__ == "__main__":
    # SECURITY: Disable debug mode in production; use environment variable
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(debug=debug_mode, host="127.0.0.1")
