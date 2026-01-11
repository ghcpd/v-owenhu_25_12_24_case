#!/usr/bin/env bash
set -euo pipefail

python -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt

# prepare sample config and DB
mkdir -p configs
cat > configs/example.yaml <<'YAML'
app: demo
api_key: "REPLACE_ME"
YAML

python - <<'PY'
import sqlite3
conn = sqlite3.connect('appdata.db')
c = conn.cursor()
c.execute('CREATE TABLE IF NOT EXISTS profiles (id INTEGER PRIMARY KEY, name TEXT, balance INTEGER)')
c.execute("INSERT OR REPLACE INTO profiles (id,name,balance) VALUES (1,'alice',100)")
conn.commit()
conn.close()
print('Environment prepared')
PY
