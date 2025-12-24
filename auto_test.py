"""Automated test runner for input_backup.py (expected to fail security checks)
and input.py (expected to pass). Produces logs/test_run.log and returns
exit code 0 only when backup fails and fixed passes.
"""
from __future__ import annotations

import io
import os
import re
import runpy
import shutil
import sqlite3
import sys
import tempfile
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Tuple

# Optional colored output (works on Windows when colorama is installed; degrades gracefully)
try:
    import colorama
    colorama.init()
    _HAS_COLOR = True
    _COL = colorama.Fore
    _RESET = colorama.Style.RESET_ALL
except Exception:
    _HAS_COLOR = False
    _COL = None
    _RESET = ""


def _color_text(msg: str, color: str) -> str:
    if not _HAS_COLOR:
        return msg
    col = getattr(_COL, color, "")
    return f"{col}{msg}{_RESET}"

ROOT = Path(__file__).resolve().parent
LOG_DIR = ROOT / "logs"
LOG_DIR.mkdir(exist_ok=True)
LOG_FILE = LOG_DIR / "test_run.log"

MODULES = [
    (ROOT / "input_backup.py", "backup"),
    (ROOT / "input.py", "fixed"),
]

# Prohibited patterns to detect (security baseline)
PROHIBITED_PATTERNS = {
    "eval_exec": re.compile(r"\b(eval|exec)\s*\("),
    "yaml_load": re.compile(r"yaml\.load\s*\("),
    "pickle_loads": re.compile(r"pickle\.loads\s*\("),
    "shell_true": re.compile(r"shell\s*=\s*True"),
    "sql_string_interp": re.compile(r"SELECT .*%\s*['\"]"),
    "unsafe_subprocess": re.compile(r"subprocess\.(Popen|call|run).*(shell\s*=)"),
    "requests_post_unchecked": re.compile(r"requests\.post\(\s*url\s*[,)]"),
}

# Hardcoded secrets regexes (reduced/heuristic)
SECRET_PATTERNS = [
    re.compile(r"PAYMENT_TOKEN\s*=\s*[\'\"]([A-Za-z0-9_\-]{8,})[\'\"]"),
    re.compile(r"MAIL_SERVER_KEY\s*=\s*[\'\"]([A-Za-z0-9_\-]{8,})[\'\"]"),
    re.compile(r"INTERNAL_AUTH\s*=\s*[\'\"]([A-Za-z0-9_\-]{6,})[\'\"]"),
    re.compile(r"-----BEGIN ([A-Z]+ )?PRIVATE KEY-----"),
]


def iso_ts() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat()


def log(msg: str) -> None:
    with LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(f"{iso_ts()} {msg}\n")


def read_file_text(p: Path) -> str:
    return p.read_text(encoding="utf-8")


def run_static_checks(source: str) -> List[str]:
    findings: List[str] = []
    for name, rx in PROHIBITED_PATTERNS.items():
        if rx.search(source):
            findings.append(f"prohibited pattern: {name}")
    for rx in SECRET_PATTERNS:
        m = rx.search(source)
        if m:
            val = m.group(1) if m.groups() else "<match>"
            # fingerprint: first4 + last4
            fp = (val[:4] + "..." + val[-4:]) if len(val) >= 8 else "<redacted>"
            findings.append(f"hardcoded-secret fingerprint={fp}")
    return findings


def run_functional_tests(module_globals: Dict, tempdir: Path) -> Tuple[bool, List[str]]:
    """Return (passed: bool, errors)

    Functional tests verify hardened behavior (strict validation + safe defaults).
    The tests are written to *fail* for the insecure backup version and *pass*
    for the fixed version.
    """
    errors: List[str] = []
    # auth_user: must produce HMAC-SHA256 (64 hex chars)
    try:
        auth = module_globals.get("auth_user")
        if not callable(auth):
            errors.append("auth_user not found/callable")
        else:
            # ensure env secret present for fixed module
            os.environ.setdefault("INTERNAL_AUTH", "test-internal-secret-0000")
            tok = auth({"username": "alice"})
            if not isinstance(tok, str) or not re.fullmatch(r"[0-9a-f]{64}", tok):
                errors.append("auth_user did not return HMAC-SHA256 hex (expected 64 hex chars)")
    except Exception as e:
        errors.append(f"auth_user raised: {e}")

    # query_profile: should accept a safe uid and return a list (DB prepared)
    try:
        # prepare a tiny sqlite DB with expected table
        db_path = tempdir / "appdata.db"
        conn = sqlite3.connect(db_path)
        conn.execute("CREATE TABLE profiles (id TEXT PRIMARY KEY, name TEXT, balance REAL)")
        conn.execute("INSERT INTO profiles (id,name,balance) VALUES (?,?,?)", ("100", "alice", 10.0))
        conn.commit()
        conn.close()
        # ensure module will point to this DB (some versions read env, some read constant)
        os.environ["APP_DB_FILE"] = str(db_path)
        # for modules that capture DB_FILE at import, ensure they use our file by running from tempdir
        qp = module_globals.get("query_profile")
        if not callable(qp):
            errors.append("query_profile not found/callable")
        else:
            out = qp("100")
            if not isinstance(out, list) or len(out) != 1:
                errors.append(f"query_profile returned unexpected: {out!r}")
    except Exception as e:
        errors.append(f"query_profile failed: {e}")

    # update_records: fixed must restrict to CONFIG_DIR; create allowed config and expect dict
    try:
        cfg_dir = tempdir / "configs"
        cfg_dir.mkdir()
        cfg_file = cfg_dir / "ok.yaml"
        cfg_file.write_text("key: val", encoding="utf-8")
        os.environ["CONFIG_DIR"] = str(cfg_dir)
        ur = module_globals.get("update_records")
        if not callable(ur):
            errors.append("update_records not found/callable")
        else:
            data = ur(str(cfg_file))
            if not isinstance(data, dict) or data.get("key") != "val":
                errors.append("update_records did not return expected dict")
            # traversal attempt must be blocked
            try:
                ur(str(cfg_file.parent.parent / "etc_passwd"))
                errors.append("update_records allowed traversal (unexpected)")
            except Exception:
                pass
    except Exception as e:
        errors.append(f"update_records failed: {e}")

    # transfer_funds: must validate notify_url (deny by default)
    try:
        tf = module_globals.get("transfer_funds")
        if not callable(tf):
            errors.append("transfer_funds not found/callable")
        else:
            # disallowed URL -> should raise
            try:
                tf({"target": "x", "amount": 1, "notify_url": "http://example.com/notify"})
                errors.append("transfer_funds allowed outbound URL without allow-listing")
            except Exception:
                pass
    except Exception as e:
        errors.append(f"transfer_funds failed: {e}")

    # export_data: must create a zip and not use shell; require DB file present
    try:
        ed = module_globals.get("export_data")
        if not callable(ed):
            errors.append("export_data not found/callable")
        else:
            # ensure DB exists (create only if missing)
            db_path = tempdir / "appdata.db"
            if not db_path.exists():
                with sqlite3.connect(db_path) as c:
                    c.execute("CREATE TABLE profiles (id TEXT)")
            os.environ["APP_DB_FILE"] = str(db_path)
            # some modules resolve DB_FILE at import; ensure correct cwd
            archive = ed("safe_name")
            arc_path = Path(archive)
            if not arc_path.exists() or arc_path.suffix != ".zip":
                errors.append("export_data did not produce expected zip archive")
    except Exception as e:
        errors.append(f"export_data failed: {e}")

    passed = len(errors) == 0
    return passed, errors


def run_tests_for_module(path: Path, expectation: str) -> int:
    """Run static + functional checks against a module file.

    Returns exit code (0 success for the module's test run, non-zero otherwise).
    """
    name = path.name
    src = read_file_text(path)
    findings = run_static_checks(src)

    buf_out = io.StringIO()
    buf_err = io.StringIO()
    exit_code = 0

    with redirect_stdout(buf_out), redirect_stderr(buf_err):
        log(f"START {name}")
        print(f"== Running tests for {name} ==")
        if findings:
            print("Static findings:")
            for f in findings:
                print(" -", f)
        else:
            print("No static findings detected.")

        # import module in isolated namespace
        tempdir = Path(tempfile.mkdtemp(prefix=f"test-{path.stem}-"))
        old_cwd = Path.cwd()
        try:
            os.chdir(tempdir)
            # copy the module under test into tempdir to avoid import-time pollution
            tgt = tempdir / path.name
            shutil.copy(path, tgt)
            # ensure environment is reasonably locked-down for the import
            env_backup = dict(os.environ)
            os.environ.pop("ALLOWED_NOTIFY_HOSTS", None)
            # For the fixed module we set safe allow-lists for functional tests
            if expectation == "fixed":
                os.environ.setdefault("ALLOWED_NOTIFY_HOSTS", "example.com,localhost")
                os.environ.setdefault("INTERNAL_AUTH", "test-internal-secret-0000")
                os.environ.setdefault("PAYMENT_TOKEN", "test-pay-0000")
            try:
                module_globals = runpy.run_path(str(tgt))
            except Exception as e:
                print(f"module import failed: {e}")
                module_globals = {}
                findings.append(f"import-failure: {e}")
            finally:
                os.environ.clear()
                os.environ.update(env_backup)

            # Functional tests (only if import succeeded)
            func_passed = False
            func_errors: List[str] = []
            if module_globals:
                func_passed, func_errors = run_functional_tests(module_globals, tempdir)
                if func_errors:
                    print("Functional errors:")
                    for e in func_errors:
                        print(" -", e)

            # Decision logic for module
            # For the *backup* module we EXPECT static/functional failures (it's insecure).
            if expectation == "backup":
                # success for backup means tests detected insecurity (i.e., findings non-empty OR functional errors)
                if findings or (not func_passed):
                    print("Expected: insecure — detected issues. (this is PASS for the backup validation)")
                    exit_code = 1  # indicates the module is insecure
                else:
                    print("No issues detected in backup (UNEXPECTED)")
                    exit_code = 0
            else:
                # expectation == fixed: we require no static findings and all functional tests to pass
                if not findings and func_passed:
                    print("No issues detected and functional tests passed.")
                    exit_code = 0
                else:
                    print("Fixed version failed checks.")
                    exit_code = 2

        finally:
            os.chdir(old_cwd)
            shutil.rmtree(tempdir, ignore_errors=True)

    # write logs: captured stdout/stderr and outcome
    out = buf_out.getvalue()
    err = buf_err.getvalue()
    log_block = [f"MODULE: {name}", f"TS: {iso_ts()}", "STDOUT:", out, "STDERR:", err]
    if findings:
        log_block.append("STATIC_FINDINGS:\n" + "\n".join(findings))
    log_msg = "\n".join(log_block)
    log(log_msg)

    # append human-friendly summary and exact final line required by spec
    if expectation == "backup":
        # For backup, treat detection of insecurity as the desired outcome (so print TEST FAILED)
        final_line = "TEST FAILED" if (findings or exit_code == 1) else "TEST PASSED"
    else:
        final_line = "TEST PASSED" if exit_code == 0 else "TEST FAILED"
    with LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(f"{iso_ts()} --- {path.name} SUMMARY ---\n")
        f.write(out)
        if err:
            f.write("\nSTDERR:\n" + err + "\n")
        f.write(final_line + "\n")

    print(f"{path.name} -> exit_code={exit_code}; final={final_line}")
    return exit_code


def detect_environment() -> Dict[str, object]:
    info = {"os": os.name, "platform": sys.platform, "in_docker": Path("/.dockerenv").exists()}
    return info


def main() -> int:
    info = detect_environment()
    log(f"Environment: {info}")
    overall = 0
    results = {}
    # Run backup first, then fixed
    for path, role in MODULES:
        rc = run_tests_for_module(path, expectation=role)
        results[role] = rc
    # Success if backup failed (rc != 0) and fixed passed (rc == 0)
    backup_failed = results.get("backup", 1) != 0
    fixed_ok = results.get("fixed", 1) == 0
    success = backup_failed and fixed_ok
    summary = f"backup_failed={backup_failed} fixed_ok={fixed_ok} overall_success={success}"
    log(summary)
    print(summary)
    return 0 if success else 3


if __name__ == "__main__":
    rc = main()
    sys.exit(rc)
