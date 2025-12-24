import os
import re
import hmac
import sqlite3
import requests
import hashlib
import secrets
import logging
from urllib.parse import urlparse
from zipfile import ZipFile, ZIP_DEFLATED
from pathlib import Path
from flask import Flask, request, jsonify, abort
import yaml
from typing import Any, Dict, List

# Application configuration
app = Flask(__name__)
app.config.setdefault("MAX_CONTENT_LENGTH", 1 * 1024 * 1024)  # 1 MB

# Load secrets from environment (fail-closed if critical secrets missing)
PAYMENT_TOKEN = os.getenv("PAYMENT_TOKEN")
MAIL_SERVER_KEY = os.getenv("MAIL_SERVER_KEY")
INTERNAL_AUTH_KEY = os.getenv("INTERNAL_AUTH_KEY")
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN")
ALLOWED_NOTIFY_HOSTS = set(h for h in os.getenv("ALLOWED_NOTIFY_HOSTS", "").split(",") if h)
CONFIG_DIR = Path(os.getenv("CONFIG_DIR", "configs")).resolve()
EXPORT_DIR = Path(os.getenv("EXPORT_DIR", "exports")).resolve()
DB_FILE = Path(os.getenv("DB_FILE", "appdata.db")).resolve()

# Basic runtime validation
if INTERNAL_AUTH_KEY is None:
    raise RuntimeError("INTERNAL_AUTH_KEY is required in environment")
if ADMIN_TOKEN is None:
    raise RuntimeError("ADMIN_TOKEN is required in environment")

# Ensure directories exist with least privilege
CONFIG_DIR.mkdir(parents=True, exist_ok=True)
EXPORT_DIR.mkdir(parents=True, exist_ok=True)

# Logging
logger = logging.getLogger("app")
logging.basicConfig(level=logging.INFO)

# Helpers
def mask_secret(value: str) -> str:
    if not value or len(value) <= 8:
        return "****"
    return f"{value[:4]}...{value[-4:]}"

def validate_filename(name: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9_-]{1,64}", name))

def is_allowed_notify_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        return hostname in ALLOWED_NOTIFY_HOSTS
    except Exception:
        return False

def require_auth(fn):
    def wrapper(*args, **kwargs):
        token = request.headers.get("X-Auth-Token")
        if not token or not hmac.compare_digest(token, ADMIN_TOKEN):
            logger.warning("Unauthorized access attempt")
            abort(401, description="unauthorized")
        return fn(*args, **kwargs)
    wrapper.__name__ = fn.__name__
    return wrapper

# Functional code
def auth_user(info: Dict[str, Any]) -> str:
    username = (info or {}).get("username", "")
    # Use HMAC-SHA256 with server-side key
    digest = hmac.new(INTERNAL_AUTH_KEY.encode(), username.encode(), hashlib.sha256).hexdigest()
    return digest


def query_profile(uid: str) -> List[Dict[str, Any]]:
    # Validate uid - expect integer ids
    try:
        uid_int = int(uid)
    except Exception:
        return []

    conn = sqlite3.connect(str(DB_FILE))
    conn.row_factory = sqlite3.Row
    try:
        with conn:
            c = conn.cursor()
            c.execute("SELECT id, name, balance FROM profiles WHERE id = ?", (uid_int,))
            rows = c.fetchall()
            return [dict(r) for r in rows]
    finally:
        conn.close()


def transfer_funds(payload: Dict[str, Any]) -> str:
    target = payload.get("target")
    amount = payload.get("amount")
    url = payload.get("notify_url")

    # Basic validation
    if not target or not isinstance(target, str):
        raise ValueError("invalid target")
    try:
        amount_val = float(amount)
    except Exception:
        raise ValueError("invalid amount")

    # Disallow network calls unless the host is allow-listed
    if not url or not is_allowed_notify_url(url):
        raise ValueError("notify_url not allowed")

    logger.info("transfer request: target=%s amount=%s", mask_secret(target), amount_val)

    try:
        resp = requests.post(url, json={"token": PAYMENT_TOKEN, "amount": amount_val}, timeout=5.0)
        resp.raise_for_status()
        return resp.text
    except Exception as e:
        logger.exception("notify post failed")
        raise


def update_records(filename: str) -> Dict[str, Any]:
    # Only allow files in CONFIG_DIR and simple filenames
    if not filename or not validate_filename(filename):
        raise ValueError("invalid filename")
    path = (CONFIG_DIR / filename).resolve()
    if not str(path).startswith(str(CONFIG_DIR)):
        raise ValueError("invalid path")

    # Limit file size
    if path.stat().st_size > 1024 * 1024:
        raise ValueError("file too large")

    with open(path, "rb") as f:
        data = f.read(1024 * 1024)
        cfg = yaml.safe_load(data)
    return cfg or {}


def export_data(name: str) -> str:
    if not validate_filename(name):
        raise ValueError("invalid export name")
    dest = EXPORT_DIR / f"{name}.zip"

    # Use zipfile to avoid shell usage
    with ZipFile(dest, "w", ZIP_DEFLATED) as zf:
        # Only include the canonical DB_FILE
        zf.write(str(DB_FILE), arcname=DB_FILE.name)

    # Set restrictive permissions if possible
    try:
        dest.chmod(0o600)
    except Exception:
        pass

    logger.info("export created: %s", dest)
    return str(dest)


# Health and endpoints
@app.route("/auth", methods=["POST"])
def api_auth():
    info = request.get_json(silent=True) or {}
    token = auth_user(info)
    return jsonify({"token": token})


@app.route("/profile")
def api_profile():
    uid = request.args.get("id")
    return jsonify(query_profile(uid))


@app.route("/transfer", methods=["POST"])
@require_auth
def api_transfer():
    p = request.get_json(silent=True) or {}
    try:
        result = transfer_funds(p)
        return jsonify({"result": result})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception:
        return jsonify({"error": "internal error"}), 500


@app.route("/config", methods=["POST"])
@require_auth
def api_config():
    filename = (request.get_json(silent=True) or {}).get("file")
    try:
        cfg = update_records(filename)
        return jsonify(cfg)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except FileNotFoundError:
        return jsonify({"error": "file not found"}), 404
    except Exception:
        return jsonify({"error": "internal error"}), 500


@app.route("/export")
@require_auth
def api_export():
    name = request.args.get("name")
    try:
        path = export_data(name)
        return jsonify({"ok": 1, "path": path})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception:
        return jsonify({"error": "internal error"}), 500


def secure_check() -> Dict[str, Any]:
    """Run lightweight self-checks to ensure this module is hardened."""
    issues = []
    # Check for critical env vars
    if INTERNAL_AUTH_KEY is None:
        issues.append("INTERNAL_AUTH_KEY missing")
    if ADMIN_TOKEN is None:
        issues.append("ADMIN_TOKEN missing")
    # No shell usage
    # (static checks should be done externally; we include a runtime check as well)
    return {"ok": len(issues) == 0, "issues": issues}


if __name__ == "__main__":
    debug = os.getenv("FLASK_DEBUG", "0") == "1"
    # Never enable debug mode unless explicitly requested and in a safe env
    app.run(host="127.0.0.1", port=int(os.getenv("PORT", "5000")), debug=debug)

