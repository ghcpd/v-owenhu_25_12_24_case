"""Hardened application - safe-by-default implementations and runtime checks.

Changes (high level):
- Secrets moved to environment (fail-closed if missing for sensitive ops).
- Auth upgraded to HMAC-SHA256 (preventing MD5 weaknesses).
- Parameterized SQL queries and input validation.
- No shell invocation; safe archiving with zipfile.
- Strict path allow-listing for config loads.
- Outbound HTTP restricted by host allow-list and timeouts.
- Debug disabled by default.
- Sensitive values redacted in logs.
"""
from __future__ import annotations

import os
import hmac
import hashlib
import sqlite3
import zipfile
import shutil
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import requests
import yaml
from flask import Flask, request, jsonify

# Application
app = Flask(__name__)

# Configuration (fail-closed defaults)
DB_FILE = os.getenv("APP_DB_FILE", "appdata.db")
INTERNAL_AUTH = os.getenv("INTERNAL_AUTH")  # required for auth HMAC
PAYMENT_TOKEN = os.getenv("PAYMENT_TOKEN")
MAIL_SERVER_KEY = os.getenv("MAIL_SERVER_KEY")
CONFIG_DIR = Path(os.getenv("CONFIG_DIR", "./configs")).resolve()
ALLOWED_NOTIFY_HOSTS = {h for h in os.getenv("ALLOWED_NOTIFY_HOSTS", "").split(",") if h}
MAX_EXPORT_NAME_LEN = 64
MAX_CONFIG_SIZE = 10 * 1024  # 10 KiB
REQUESTS_TIMEOUT = float(os.getenv("REQUESTS_TIMEOUT", "5"))

# Helper utilities

def _mask_secret(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    s = str(value)
    if len(s) <= 8:
        return s[0:1] + "..." + s[-1:]
    return s[:4] + "..." + s[-4:]


def _ensure_auth_secret() -> None:
    if not INTERNAL_AUTH:
        raise RuntimeError("INTERNAL_AUTH is required by policy for secure operation")


def _is_allowed_notify_url(url: str) -> bool:
    try:
        p = urlparse(url)
    except Exception:
        return False
    if p.scheme not in ("http", "https"):
        return False
    host = p.hostname or ""
    # if ALLOWED_NOTIFY_HOSTS not set, deny all outbound by default (fail-closed)
    return host in ALLOWED_NOTIFY_HOSTS


# --- Application functions (hardened) ---

def auth_user(info: Dict[str, Any]) -> str:
    """Return an HMAC-SHA256 token for the provided username.

    - Enforces allow-list on username characters and length.
    - Requires INTERNAL_AUTH in the environment (fail-closed).
    """
    _ensure_auth_secret()
    username = (info or {}).get("username", "")
    if not isinstance(username, str) or len(username) > 128:
        raise ValueError("invalid username")
    # allow only common username characters
    if not all(c.isalnum() or c in "._-@" for c in username):
        raise ValueError("invalid username characters")
    hm = hmac.new(INTERNAL_AUTH.encode(), username.encode(), hashlib.sha256)
    return hm.hexdigest()


def query_profile(uid: str) -> list:
    """Query a user profile using a parameterized query and tight validation.

    DB path is resolved at call time to allow runtime overrides (safe-for-test and runtime
    configuration)."""
    if uid is None:
        raise ValueError("uid required")
    # allow-list: numeric ids or short alphanumeric ids
    if not (uid.isdigit() or (1 <= len(uid) <= 64 and all(c.isalnum() or c in "-_" for c in uid))):
        raise ValueError("invalid uid")
    db_path = Path(os.getenv("APP_DB_FILE", DB_FILE)).resolve()
    conn = sqlite3.connect(db_path, isolation_level=None)
    try:
        c = conn.cursor()
        c.execute("SELECT id, name, balance FROM profiles WHERE id = ?", (uid,))
        return c.fetchall()
    finally:
        conn.close()


def transfer_funds(payload: Dict[str, Any]) -> str:
    """Transfer funds with strict validation and no secret leakage.

    Outbound network is blocked unless ALLOWED_NOTIFY_HOSTS is explicitly set.
    """
    if not isinstance(payload, dict):
        raise ValueError("invalid payload")
    target = payload.get("target")
    amount = payload.get("amount")
    if not isinstance(amount, (int, float)) or amount <= 0 or amount > 1_000_000:
        raise ValueError("invalid amount")
    notify_url = payload.get("notify_url")
    if not notify_url or not _is_allowed_notify_url(notify_url):
        raise ValueError("notify_url not allowed")
    # do not log secrets
    print(f"transfer:target={target!s}:amount={amount}")
    token = PAYMENT_TOKEN
    if not token:
        raise RuntimeError("payment token not configured")
    # send minimal data and never print token
    resp = requests.post(notify_url, json={"amount": amount}, timeout=REQUESTS_TIMEOUT)
    resp.raise_for_status()
    return resp.text


def update_records(path: str) -> dict:
    """Load YAML only from files inside the configured CONFIG_DIR; block traversal.

    CONFIG_DIR is resolved at call time to allow runtime overrides for testing and
    runtime configuration management.
    """
    if not isinstance(path, str) or len(path) > 260:
        raise ValueError("invalid path")
    config_dir = Path(os.getenv("CONFIG_DIR", str(CONFIG_DIR))).resolve()
    candidate = (Path(path)).resolve()
    if not str(candidate).startswith(str(config_dir)):
        raise PermissionError("path not allowed")
    if not candidate.exists() or not candidate.is_file():
        raise FileNotFoundError("config not found")
    if candidate.stat().st_size > MAX_CONFIG_SIZE:
        raise ValueError("config too large")
    with candidate.open("r", encoding="utf-8") as f:
        # safe_load is used; YAML load-time plugins are not allowed in this design
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise ValueError("invalid config format")
    return data


def export_data(name: str) -> Path:
    """Create a ZIP archive of application data in a safe directory (no shell)."""
    if not isinstance(name, str) or len(name) == 0 or len(name) > MAX_EXPORT_NAME_LEN:
        raise ValueError("invalid name")
    # allow only safe filename characters
    if not all(c.isalnum() or c in "-_" for c in name):
        raise ValueError("invalid characters in name")
    out_dir = Path("./exports").resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    archive_path = out_dir / f"{name}.zip"
    # use zipfile (no shell) and include only the configured DB file
    db_path = Path(os.getenv("APP_DB_FILE", DB_FILE)).resolve()
    if not db_path.exists():
        raise FileNotFoundError("database file missing")
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.write(db_path, arcname=db_path.name)
    return archive_path


# --- HTTP endpoints (preserve surface area) ---

@app.route("/auth", methods=["POST"])
def api_auth():
    info = request.get_json(force=True)
    return jsonify({"token": auth_user(info)})


@app.route("/profile")
def api_profile():
    uid = request.args.get("id")
    return jsonify(query_profile(uid))


@app.route("/transfer", methods=["POST"])
def api_transfer():
    p = request.get_json(force=True)
    return jsonify({"result": transfer_funds(p)})


@app.route("/config", methods=["POST"])
def api_config():
    path = request.get_json(force=True).get("file")
    return jsonify(update_records(path))


@app.route("/export")
def api_export():
    name = request.args.get("name")
    archive = export_data(name)
    return jsonify({"ok": 1, "archive": str(archive)})


# Do not run with debug=True in production
def _run():
    host = os.getenv("APP_HOST", "127.0.0.1")
    port = int(os.getenv("APP_PORT", "5000"))
    app.run(host=host, port=port, debug=False)


if __name__ == "__main__":
    _run()

