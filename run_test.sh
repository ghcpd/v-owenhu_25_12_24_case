#!/usr/bin/env bash
set -euo pipefail

# Set test environment (use ephemeral secrets)
export INTERNAL_AUTH_KEY="test_internal_key_$(openssl rand -hex 4 2>/dev/null || echo 1234)"
export ADMIN_TOKEN="test_admin_token_$(openssl rand -hex 4 2>/dev/null || echo abcd)"
export PAYMENT_TOKEN="test_payment_$(openssl rand -hex 4 2>/dev/null || echo 5678)"
export ALLOWED_NOTIFY_HOSTS="localhost"
export DB_FILE="appdata.db"

mkdir -p logs
python auto_test.py
