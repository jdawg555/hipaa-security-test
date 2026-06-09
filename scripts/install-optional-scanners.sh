#!/usr/bin/env bash
# Install optional OSS scanners for hipaa-audit evidence collection.
# Run once on a developer machine or CI image. All tools are optional.
set -euo pipefail

echo "==> Python scanners (pip)"
pip install -q prowler-cloud checkov 2>/dev/null || pip install prowler-cloud checkov

echo "==> Trivy"
if command -v trivy &>/dev/null; then
  echo "    already installed: $(trivy --version | head -1)"
elif command -v brew &>/dev/null; then
  brew install trivy
else
  echo "    install manually: https://aquasecurity.github.io/trivy/latest/getting-started/installation/"
fi

echo "==> OSV-Scanner"
if command -v osv-scanner &>/dev/null; then
  echo "    already installed"
elif command -v brew &>/dev/null; then
  brew install osv-scanner
else
  echo "    install manually: https://google.github.io/osv-scanner/installation/"
fi

echo ""
echo "Done. Run: bash scripts/collect-external-evidence.sh ."
