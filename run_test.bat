@echo off
python auto_test.py
if %ERRORLEVEL% neq 0 exit /b %ERRORLEVEL%
