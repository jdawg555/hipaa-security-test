#!/usr/bin/env bash
# Collect OSS scanner evidence for hipaa-audit integrations.
# Run from your application repo root after hipaa-audit init.
# All tools are optional — install only what you use.
set -euo pipefail

ROOT="${1:-.}"
cd "$ROOT"
mkdir -p evidence/prowler evidence/prowler-azure evidence/prowler-gcp evidence/trivy evidence/osv evidence/latest

echo "==> Prowler (AWS HIPAA mode)"
if command -v prowler &>/dev/null; then
  prowler aws --compliance hipaa_aws -M json -o evidence/prowler/ --output-formats json-ocsf || true
else
  echo "    skip — prowler not installed (pip install prowler-cloud)"
fi

echo "==> Prowler (Azure HIPAA mode)"
if command -v prowler &>/dev/null; then
  prowler azure --compliance hipaa_azure -M json -o evidence/prowler-azure/ --output-formats json-ocsf || true
else
  echo "    skip — prowler not installed"
fi

echo "==> Prowler (GCP HIPAA mode)"
if command -v prowler &>/dev/null; then
  prowler gcp --compliance hipaa_gcp -M json -o evidence/prowler-gcp/ --output-formats json-ocsf || true
else
  echo "    skip — prowler not installed"
fi

echo "==> Checkov (IaC)"
if command -v checkov &>/dev/null; then
  mkdir -p evidence/checkov
  SCAN_DIR="."
  for candidate in examples/terraform-minimal terraform infra; do
    if [[ -d "$candidate" ]]; then
      SCAN_DIR="$candidate"
      break
    fi
  done
  checkov -d "$SCAN_DIR" --framework terraform -o json --output-file-path evidence/checkov || true
else
  echo "    skip — checkov not installed (pip install checkov)"
fi

echo "==> Trivy (filesystem)"
if command -v trivy &>/dev/null; then
  trivy fs --format json --output evidence/trivy/report.json . || true
else
  echo "    skip — trivy not installed"
fi

echo "==> OSV-Scanner"
if command -v osv-scanner &>/dev/null; then
  osv-scanner --format json --output evidence/osv/report.json -r . || true
else
  echo "    skip — osv-scanner not installed"
fi

echo "==> ComplianceKit (HIPAA evidence pack)"
if command -v compliancekit &>/dev/null; then
  PERIOD="$(date +%Y)-Q$(( (10#$(date +%m) - 1) / 3 + 1 ))"
  compliancekit evidence --output "evidence/compliancekit/${PERIOD}" 2>/dev/null || \
    echo "    skip — run compliancekit scan first or check cloud credentials"
else
  echo "    skip — compliancekit not installed (see github.com/darpanzope/compliancekit)"
fi

echo "==> hipaa-audit"
if command -v hipaa-audit &>/dev/null; then
  hipaa-audit scan . -o evidence/latest
else
  echo "    skip — pip install -e . from hipaa-security-test"
fi

echo "Done. Open evidence/latest/dashboard.html"
