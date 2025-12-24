import os
import sys
import platform
import shutil
from datetime import datetime
import sqlite3
import importlib

LOG_FILE = "logs/test_run.log"
os.makedirs("logs", exist_ok=True)

def log(message):
    timestamp = datetime.now().isoformat()
    with open(LOG_FILE, "a") as f:
        f.write(f"{timestamp}: {message}\n")
    # Also print to console with color
    if "vulnerability detected" in message:
        print(f"\033[91m{message}\033[0m")  # Red for vuln
    elif "TEST FAILED" in message:
        print(f"\033[91m{message}\033[0m")
    elif "TEST PASSED" in message:
        print(f"\033[92m{message}\033[0m")  # Green for passed
    else:
        print(message)

def is_docker():
    return os.path.exists('/.dockerenv')

def detect_os():
    return platform.system()

def setup_db():
    conn = sqlite3.connect('appdata.db')
    c = conn.cursor()
    c.execute('CREATE TABLE IF NOT EXISTS profiles (id TEXT, name TEXT, balance REAL)')
    c.execute("INSERT OR IGNORE INTO profiles VALUES ('1', 'test', 100.0)")
    conn.commit()
    conn.close()

def test_vulnerabilities(input_module):
    vuln_found = False

    # Test SQLi
    try:
        input_module.query_profile("1' OR '1'='1")
        vuln_found = True
        log("SQLi vulnerability detected")
    except ValueError:
        pass  # Expected in fixed
    except:
        vuln_found = True  # Other errors still vuln

    # Test command injection
    try:
        input_module.export_data("test;echo hacked")
        vuln_found = True
        log("Command injection vulnerability detected")
    except ValueError:
        pass
    except:
        vuln_found = True

    # Test path traversal
    try:
        input_module.update_records('../../../test.yaml')
        vuln_found = True
        log("Path traversal vulnerability detected")
    except ValueError:
        pass
    except:
        vuln_found = True

    # Test SSRF
    try:
        input_module.transfer_funds({"target": "test", "amount": 100, "notify_url": "http://127.0.0.1:8080"})
        vuln_found = True
        log("SSRF vulnerability detected")
    except ValueError:
        pass
    except:
        vuln_found = True

    return vuln_found

def run_tests_for_version(version_file):
    if version_file != 'input.py':
        # For backup
        if os.path.exists('input.py'):
            shutil.move('input.py', 'input_temp.py')
        shutil.copy(version_file, 'input.py')

    log(f"Testing {version_file}")

    # Reload the module
    import input
    importlib.reload(input)

    vuln = test_vulnerabilities(input)

    if version_file != 'input.py':
        # Restore
        os.remove('input.py')
        if os.path.exists('input_temp.py'):
            shutil.move('input_temp.py', 'input.py')

    return vuln

def main():
    os_info = detect_os()
    docker_info = is_docker()
    log(f"OS: {os_info}, Docker: {docker_info}")

    setup_db()

    # Test backup first
    backup_vuln = run_tests_for_version('input_backup.py')
    if backup_vuln:
        log("TEST FAILED")
    else:
        log("TEST PASSED")

    # Test fixed
    fixed_vuln = run_tests_for_version('input.py')
    if not fixed_vuln:
        log("TEST PASSED")
    else:
        log("TEST FAILED")

    # Overall success if backup has vuln and fixed does not
    if backup_vuln and not fixed_vuln:
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == "__main__":
    main()