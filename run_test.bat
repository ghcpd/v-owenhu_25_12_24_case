@echo off
REM Set ephemeral test env vars (Windows power shell not used here)
set INTERNAL_AUTH_KEY=test_internal_key_1234
set ADMIN_TOKEN=test_admin_token_abcd
set PAYMENT_TOKEN=test_payment_5678
set ALLOWED_NOTIFY_HOSTS=localhost
set DB_FILE=appdata.db

if not exist logs mkdir logs
python auto_test.py
