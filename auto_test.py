#!/usr/bin/env python3
"""Automated test runner for input_backup.py (expected to FAIL) and input.py (expected to PASS).
Writes logs to logs/test_run.log with ISO-8601 timestamps and final TEST PASSED / TEST FAILED lines.
"""
import importlib.util
import os
import sys
import sqlite3
import tempfile
import traceback
from datetime import datetime
from contextlib import redirect_stdout, redirect_stderr

ROOT = os.path.dirname(__file__)
LOG_DIR = os.path.join(ROOT, "logs")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "test_run.log")

MODULE_FILES = [
    ("input_backup", os.path.join(ROOT, "input_backup.py")),
    ("input", os.path.join(ROOT, "input.py")),
]

# --- helpers -------------------------------------------------

def ts():
    return datetime.utcnow().isoformat() + "Z"


# ANSI color helpers (prints color only when stdout is a tty)
CSI = "\x1b["
RESET = CSI + "0m"
GREEN = CSI + "32m"
YELLOW = CSI + "33m"
RED = CSI + "31m"


def _supports_color() -> bool:
    try:
        is_tty = sys.stdout.isatty()
    except Exception:
        is_tty = False
    if not is_tty:
        return False
    if os.name == "nt":
        # attempt to enable ANSI processing on Windows consoles
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            handle = kernel32.GetStdHandle(-11)
            mode = ctypes.c_uint()
            if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                kernel32.SetConsoleMode(handle, mode.value | 0x0004)
                return True
        except Exception:
            return False
    return True


def _colorize(text: str, color_code: str) -> str:
    return text if not _supports_color() else f"{color_code}{text}{RESET}"


def load_module_from_path(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    loader = spec.loader
    assert loader is not None
    loader.exec_module(mod)
    return mod


# --- security tests (return True if test PASSES) ------------

def test_sql_injection_prevention(mod):
    # create a temp DB and inject two rows
    db_path = os.path.join(tempfile.gettempdir(), "test_profiles.db")
    if os.path.exists(db_path):
        os.remove(db_path)
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE profiles (id INTEGER PRIMARY KEY, name TEXT, balance INTEGER)")
    conn.execute("INSERT INTO profiles (id, name, balance) VALUES (1, 'alice', 100)")
    conn.execute("INSERT INTO profiles (id, name, balance) VALUES (2, 'bob', 200)")
    conn.commit()
    conn.close()
    # point module to temp DB
    setattr(mod, "DB_FILE", db_path)
    # malicious payload that would succeed against string-formatted SQL
    res = mod.query_profile("1' OR '1'='1")
    # secure behavior: should NOT return rows for injection payload
    return len(res) == 0


def test_export_name_validation(mod):
    # valid name should succeed
    tmpdb = os.path.join(tempfile.gettempdir(), "test_db_for_export.db")
    if not os.path.exists(tmpdb):
        conn = sqlite3.connect(tmpdb)
        conn.execute("CREATE TABLE IF NOT EXISTS t (id INTEGER)")
        conn.commit()
        conn.close()
    setattr(mod, "DB_FILE", tmpdb)
    ok = False
    try:
        a = mod.export_data("safe_name")
        ok = os.path.exists(a)
    except Exception:
        ok = False
    # invalid name must be rejected (no command injection)
    rejected = False
    try:
        mod.export_data("bad;name")
    except Exception:
        rejected = True
    return ok and rejected


def test_notify_url_allowlist(mod):
    # by secure design, outbound notify is DENY-by-default; transfer_funds should reject unknown host
    payload = {"target": "x", "amount": 1, "notify_url": "http://example.com/callback"}
    try:
        mod.transfer_funds(payload)
    except Exception:
        return True
    return False


def test_update_records_sanitization(mod):
    # create configs dir and a config file containing a secret
    cfgdir = os.path.join(os.path.dirname(mod.__file__), "configs")
    os.makedirs(cfgdir, exist_ok=True)
    cfgpath = os.path.join(cfgdir, "danger.yaml")
    with open(cfgpath, "w", encoding="utf-8") as f:
        f.write("api_key: SECRET_VALUE\nnormal: ok\n")
    try:
        out = mod.update_records("danger.yaml")
    except Exception:
        return False
    # secure behavior: api_key must be redacted
    return out.get("api_key") == "<REDACTED>"


def test_auth_token_strength(mod):
    t = mod.auth_user({"username": "alice"})
    # expect HMAC-SHA256 hex (64 chars)
    return isinstance(t, str) and len(t) >= 64


def test_prompt_injection_defense(mod):
    # ensure that update_records (and other I/O) do not leak internal secrets
    cfgdir = os.path.join(os.path.dirname(mod.__file__), "configs")
    os.makedirs(cfgdir, exist_ok=True)
    path = os.path.join(cfgdir, "leak.yaml")
    with open(path, "w", encoding="utf-8") as f:
        f.write("system_prompt: 'do not override system'\ninternal: '" + getattr(mod, "INTERNAL_AUTH", "XXX") + "'\n")
    try:
        out = mod.update_records("leak.yaml")
    except Exception:
        return False
    # internal should be redacted or not returned verbatim
    return out.get("internal") != getattr(mod, "INTERNAL_AUTH", "XXX")


TESTS = [
    ("SQL injection prevention", test_sql_injection_prevention),
    ("Export name validation", test_export_name_validation),
    ("Notify URL allowlist (deny-by-default)", test_notify_url_allowlist),
    ("Update records sanitization", test_update_records_sanitization),
    ("Auth token strength (HMAC)", test_auth_token_strength),
    ("Prompt-injection / secret leakage check", test_prompt_injection_defense),
]


# --- runner --------------------------------------------------

def run_tests_for_module(mod_name, mod_path):
    start = datetime.utcnow()
    captured_out = []
    success = True
    try:
        mod = load_module_from_path(mod_name, mod_path)
    except Exception as e:
        captured_out.append(f"{ts()} ERROR loading module: {e}\n")
        return False, "\n".join(captured_out)

    per_case = []
    for idx, (desc, test) in enumerate(TESTS, start=1):
        t0 = datetime.utcnow()
        try:
            ok = test(mod)
            status = "PASS" if ok else "FAIL"
            if not ok:
                success = False
            captured_out.append(f"{ts()} {mod_name} - {desc}: {status}")
            per_case.append((idx, desc, ok))
        except Exception:
            success = False
            captured_out.append(f"{ts()} {mod_name} - {desc}: EXCEPTION\n" + traceback.format_exc())
            per_case.append((idx, desc, False))
        t1 = datetime.utcnow()

    # Print a colored, enumerated list of test cases for this module
    print(f"\n[{mod_name}] Test cases:")
    for idx, desc, ok in per_case:
        status_str = "PASS" if ok else "FAIL"
        col = GREEN if ok else RED
        print(f" {idx:2d}. {desc} - {_colorize(status_str, col)}")

    return success, "\n".join(captured_out)


def main():
    overall_success = False
    # run input_backup then input
    results = []
    for name, path in MODULE_FILES:
        with open(LOG_FILE, "a", encoding="utf-8") as lf:
            lf.write(f"{ts()} Running tests for {name}\n")
        success, out = run_tests_for_module(name, path)
        with open(LOG_FILE, "a", encoding="utf-8") as lf:
            lf.write(out + "\n")
            lf.write(f"{ts()} {'TEST PASSED' if success else 'TEST FAILED'}\n")
        results.append((name, success))
    # overall: backup MUST fail, fixed MUST pass
    backup_failed = not results[0][1]
    fixed_passed = results[1][1]
    overall_success = backup_failed and fixed_passed
    with open(LOG_FILE, "a", encoding="utf-8") as lf:
        lf.write(f"{ts()} Overall result: {'SUCCESS' if overall_success else 'FAILURE'}\n")
    return 0 if overall_success else 1


if __name__ == "__main__":
    exit(main())
