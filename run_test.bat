@echo off
REM Windows test runner script

echo Running security audit tests on Windows...

REM Create venv if it doesn't exist
if not exist "venv" (
    python -m venv venv
)

REM Activate virtual environment
call venv\Scripts\activate.bat

REM Run auto_test.py
python auto_test.py

echo Test suite completed. Check logs/test_run.log for details.
