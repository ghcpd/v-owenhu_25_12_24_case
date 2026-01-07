@echo off
REM Windows test runner
set PYTHON=python
%PYTHON% auto_test.py
if ERRORLEVEL 1 exit /b %ERRORLEVEL%
