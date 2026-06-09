#!/usr/bin/env bash
# End-to-end HIPAA compliance workflow (v1.8)
set -euo pipefail

ROOT="${1:-.}"
cd "$ROOT"

echo "==> 1/10 Collect external scanner evidence (optional tools)"
bash scripts/collect-external-evidence.sh .

echo "==> 2/10 Compliance registers (examples for smoke)"
cp -n compliance/vendors.example.yaml compliance/vendors.yaml 2>/dev/null || true
cp -n compliance/access-reviews.example.yaml compliance/access-reviews.yaml 2>/dev/null || true
cp -n compliance/saas-inventory.example.yaml compliance/saas-inventory.yaml 2>/dev/null || true
cp -n compliance/devices.example.yaml compliance/devices.yaml 2>/dev/null || true
cp -n compliance/vendor-questionnaires.example.yaml compliance/vendor-questionnaires.yaml 2>/dev/null || true
hipaa-audit vendor list . || true
hipaa-audit vendor questionnaires . || true
hipaa-audit access-review list . || true
hipaa-audit apps list . || true
hipaa-audit devices list . || true
hipaa-audit framework soc2 || true

echo "==> 3/10 Run hipaa-audit scan + posture history + task sync"
hipaa-audit scan . -o evidence/latest

echo "==> 4/10 List open remediation tasks"
hipaa-audit tasks list .

echo "==> 5/10 Export for Probo GRC platform"
hipaa-audit export probo -o evidence/latest/probo-import.json

echo "==> 6/10 Auditor evidence bundle"
cp -n compliance/certifications.example.yaml compliance/certifications.yaml 2>/dev/null || true
hipaa-audit export auditor -o evidence/latest/auditor-bundle.zip

echo "==> 7/10 Trust center"
hipaa-audit trust publish .

echo "==> 8/10 Posture snapshot"
cat evidence/history/posture-latest.json 2>/dev/null | head -20 || true

echo "==> 9/10 Probo catalog coverage"
hipaa-audit catalog coverage

echo "==> 10/10 Done"
echo "    Dashboard:    evidence/latest/dashboard.html"
echo "    Trust center: compliance/trust-center/index.html"
echo "    Auditor ZIP:  evidence/latest/auditor-bundle.zip"
echo "    Probo:        evidence/latest/probo-import.json"
