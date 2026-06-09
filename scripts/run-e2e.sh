#!/usr/bin/env bash
# End-to-end HIPAA compliance workflow (v1.6)
set -euo pipefail

ROOT="${1:-.}"
cd "$ROOT"

echo "==> 1/8 Collect external scanner evidence (optional tools)"
bash scripts/collect-external-evidence.sh .

echo "==> 2/8 Vendor + access review registers (examples for smoke)"
cp -n compliance/vendors.example.yaml compliance/vendors.yaml 2>/dev/null || true
cp -n compliance/access-reviews.example.yaml compliance/access-reviews.yaml 2>/dev/null || true
hipaa-audit vendor list . || true
hipaa-audit access-review list . || true

echo "==> 3/8 Run hipaa-audit scan + posture history + task sync"
hipaa-audit scan . -o evidence/latest

echo "==> 4/8 List open remediation tasks"
hipaa-audit tasks list .

echo "==> 5/8 Export for Probo GRC platform"
hipaa-audit export probo -o evidence/latest/probo-import.json

echo "==> 6/8 Posture snapshot"
cat evidence/history/posture-latest.json 2>/dev/null | head -20 || true

echo "==> 7/8 Probo catalog coverage"
hipaa-audit catalog coverage

echo "==> 8/8 Done"
echo "    Dashboard: evidence/latest/dashboard.html"
echo "    Probo:     evidence/latest/probo-import.json"
echo "    Tasks:     compliance/tasks.yaml"
echo "    Vendors:   compliance/vendors.yaml"
echo "    Access:    compliance/access-reviews.yaml"
