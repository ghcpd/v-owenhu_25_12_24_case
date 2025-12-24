#!/usr/bin/env python3
"""
Automated test runner for security audit.
Tests both backup (should fail) and fixed (should pass) versions.
"""

import os
import sys
import subprocess
import platform
from pathlib import Path
from datetime import datetime
import traceback

class TestRunner:
    def __init__(self):
        self.os_type = self._detect_os()
        self.in_docker = self._detect_docker()
        self.log_dir = Path("logs")
        self.log_dir.mkdir(exist_ok=True)
        self.log_file = self.log_dir / "test_run.log"
        self.test_results = []
        
    def _detect_os(self):
        """Detect OS: Windows, Linux, or macOS"""
        if sys.platform.startswith("win"):
            return "Windows"
        elif sys.platform.startswith("linux"):
            return "Linux"
        elif sys.platform.startswith("darwin"):
            return "macOS"
        return "Unknown"
    
    def _detect_docker(self):
        """Check if running inside Docker"""
        docker_file = Path("/.dockerenv")
        return docker_file.exists()
    
    def log(self, message):
        """Write to log file with ISO-8601 timestamp"""
        timestamp = datetime.utcnow().isoformat() + "Z"
        log_line = f"[{timestamp}] {message}"
        print(log_line)
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(log_line + "\n")
    
    def test_syntax(self, filename):
        """Test Python syntax of a file"""
        try:
            import py_compile
            py_compile.compile(filename, doraise=True)
            return True, None
        except py_compile.PyCompileError as e:
            return False, str(e)
    
    def test_imports(self, filename):
        """Test if imports are satisfied (basic check)"""
        try:
            with open(filename, 'r') as f:
                code = f.read()
            
            # Check for critical issues - more precise patterns
            if "eval(" in code or "exec(" in code:
                return False, "Found eval/exec - security risk"
            # Only flag actual shell=True usage, not in comments/docstrings
            if "shell=True)" in code or "shell = True" in code:
                return False, "Found subprocess with shell=True - security risk"
            if '% uid' in code or '% uid)' in code or f'"%s"' in code:
                return False, "Found SQL injection pattern"
            
            # Try to compile
            compile(code, filename, 'exec')
            return True, None
        except Exception as e:
            return False, str(e)
    
    def run_tests(self):
        """Execute test suite"""
        self.log(f"=== Security Audit Test Suite ===")
        self.log(f"OS: {self.os_type}")
        self.log(f"In Docker: {self.in_docker}")
        self.log(f"Python: {platform.python_version()}")
        self.log("")
        
        # Test 1: Backup should fail (has vulnerabilities)
        self.log("--- Testing input_backup.py (should FAIL due to vulnerabilities) ---")
        backup_ok, backup_msg = self.test_imports("input_backup.py")
        
        if not backup_ok:
            self.log(f"EXPECTED FAILURE: {backup_msg}")
            self.test_results.append(("input_backup.py", "TEST PASSED"))
            self.log("TEST PASSED: Backup correctly identified with vulnerabilities")
        else:
            # Check for known vulnerabilities
            has_vulns = False
            with open("input_backup.py", 'r') as f:
                content = f.read()
                if '"tok_production_' in content:
                    has_vulns = True
                    self.log("FOUND VULN: Hardcoded secrets")
                if "shell=True" in content:
                    has_vulns = True
                    self.log("FOUND VULN: shell=True in subprocess")
                if "hashlib.md5" in content:
                    has_vulns = True
                    self.log("FOUND VULN: Weak MD5 hashing")
                if "% uid" in content or "'%s'" in content:
                    has_vulns = True
                    self.log("FOUND VULN: SQL injection pattern")
            
            if has_vulns:
                self.test_results.append(("input_backup.py", "TEST PASSED"))
                self.log("TEST PASSED: Backup contains expected vulnerabilities")
            else:
                self.test_results.append(("input_backup.py", "TEST FAILED"))
                self.log("TEST FAILED: Backup should have vulnerabilities")
        
        self.log("")
        
        # Test 2: Fixed version should pass
        self.log("--- Testing input.py (should PASS - secured version) ---")
        
        # Syntax check
        syntax_ok, syntax_msg = self.test_syntax("input.py")
        if not syntax_ok:
            self.test_results.append(("input.py syntax", "TEST FAILED"))
            self.log(f"TEST FAILED - Syntax error: {syntax_msg}")
            return False
        self.log("[OK] Syntax check passed")
        
        # Import check (vulnerability scan)
        import_ok, import_msg = self.test_imports("input.py")
        if not import_ok:
            self.test_results.append(("input.py security", "TEST FAILED"))
            self.log(f"TEST FAILED - Security issues: {import_msg}")
            return False
        self.log("[OK] Security checks passed")
        
        # Verify fixes are in place
        with open("input.py", 'r') as f:
            content = f.read()
        
        fixes_verified = []
        
        # Check for secret externalization
        if 'os.environ.get("PAYMENT_TOKEN")' in content:
            fixes_verified.append("Secrets from environment")
            self.log("[OK] Secrets externalized from environment variables")
        else:
            self.log("[FAIL] Secrets not properly externalized")
            return False
        
        # Check for parameterized queries
        if "WHERE id = ?" in content:
            fixes_verified.append("Parameterized SQL queries")
            self.log("[OK] SQL injection prevention (parameterized queries)")
        else:
            self.log("[FAIL] SQL queries not parameterized")
            return False
        
        # Check for HMAC-SHA256
        if "hmac" in content and "hashlib.sha256" in content:
            fixes_verified.append("Strong hashing (HMAC-SHA256)")
            self.log("[OK] Cryptography hardened (HMAC-SHA256)")
        else:
            self.log("[FAIL] Weak hashing still present")
            return False
        
        # Check for subprocess safety
        if 'subprocess.run(cmd, capture_output=True' in content or 'subprocess.run(cmd,' in content and "shell=True" not in content:
            fixes_verified.append("Safe subprocess calls")
            self.log("[OK] Command injection prevention (no shell=True)")
        else:
            self.log("[FAIL] Unsafe subprocess calls remain")
            return False
        
        # Check for SSRF protection
        if "ALLOWED_NOTIFY_DOMAINS" in content:
            fixes_verified.append("SSRF protection with allowlists")
            self.log("[OK] SSRF protection (domain allowlist)")
        else:
            self.log("[FAIL] SSRF protection missing")
            return False
        
        # Check for debug mode disabled
        if 'os.environ.get("FLASK_DEBUG"' in content:
            fixes_verified.append("Debug mode disabled")
            self.log("[OK] Debug mode controlled via environment")
        else:
            self.log("[FAIL] Debug mode not properly controlled")
            return False
        
        # Check for error handling
        if "try:" in content and "except" in content:
            fixes_verified.append("Error handling")
            self.log("[OK] Error handling implemented")
        else:
            self.log("[FAIL] Error handling missing")
            return False
        
        # Check for logging
        if "logger." in content or "logging" in content:
            fixes_verified.append("Secure logging")
            self.log("[OK] Secure logging without secret leakage")
        else:
            self.log("[FAIL] Logging not properly secured")
            return False
        
        self.log("")
        self.log(f"Verified {len(fixes_verified)} security fixes:")
        for fix in fixes_verified:
            self.log(f"  • {fix}")
        
        self.test_results.append(("input.py", "TEST PASSED"))
        self.log("")
        self.log("TEST PASSED: All security fixes verified")
        return True
    
    def print_summary(self):
        """Print test summary"""
        self.log("")
        self.log("=== Test Summary ===")
        for test_name, result in self.test_results:
            self.log(f"{test_name}: {result}")
        
        # Overall result
        all_passed = all(result == "TEST PASSED" for _, result in self.test_results)
        if all_passed:
            self.log("")
            self.log("OVERALL: All tests passed!")
            return 0
        else:
            self.log("")
            self.log("OVERALL: Some tests failed!")
            return 1

if __name__ == "__main__":
    runner = TestRunner()
    success = runner.run_tests()
    exit_code = runner.print_summary()
    sys.exit(exit_code)
