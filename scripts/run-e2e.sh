#!/usr/bin/env bash
# End-to-end HIPAA compliance workflow (v1.4)
set -euo pipefail

ROOT="${1:-.}"
cd "$ROOT"

echo "==> 1/6 Collect external scanner evidence (optional tools)"
bash scripts/collect-external-evidence.sh .

echo "==> 2/6 Run hipaa-audit scan + posture history + task sync"
hipaa-audit scan . -o evidence/latest

echo "==> 3/6 List open remediation tasks"
hipaa-audit tasks list .

echo "==> 4/6 Export for Probo GRC platform"
hipaa-audit export probo -o evidence/latest/probo-import.json

echo "==> 5/6 Posture snapshot"
cat evidence/history/posture-latest.json 2>/dev/null | head -20 || true

echo "==> 6/6 Done"
echo "    Dashboard: evidence/latest/dashboard.html"
echo "    Probo:     evidence/latest/probo-import.json"
echo "    Tasks:     compliance/tasks.yaml"
