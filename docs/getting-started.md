# Getting Started

## Quick start (5 minutes)

```bash
git clone https://github.com/jdawg555/hipaa-security-test.git
cd hipaa-security-test
pip install -e .

# Audit this repo (self-test)
hipaa-audit scan .

# Bootstrap your healthcare app repo
cd /path/to/your-app
hipaa-audit init
hipaa-audit scan .
open evidence/latest/dashboard.html
```

## What you get (Vanta/Drata-style, free)

| Capability | Vanta/Drata | hipaa-audit |
|------------|-------------|-------------|
| Control library mapped to HIPAA | ✅ Paid | ✅ Open source YAML |
| Automated technical checks | ✅ | ✅ AWS, GitHub, repo |
| Policy templates | ✅ | ✅ 12 starter policies |
| SRA / risk / BAA registers | ✅ | ✅ Markdown templates |
| Evidence export | ✅ | ✅ JSON + HTML dashboard |
| Continuous monitoring | ✅ | ✅ GitHub Actions weekly |
| Personnel training tracking | ✅ | Manual (template) |
| Auditor portal | ✅ | HTML dashboard + JSON |
| **Price** | $10k+/yr | **$0** |

## Enable AWS checks

```bash
pip install hipaa-audit[aws]
aws configure  # or OIDC in CI

cat >> hipaa-audit.yaml <<EOF
aws:
  enabled: true
  region: us-east-1
EOF

hipaa-audit scan .
```

## Enable GitHub checks

```bash
gh auth login
# or export GITHUB_TOKEN=...

cat >> hipaa-audit.yaml <<EOF
github:
  enabled: true
  repo: your-org/your-repo
EOF

hipaa-audit scan .
```

## Integrate Prowler / Trivy / OSV (optional)

Enable integrations in `hipaa-audit.yaml`, then collect evidence:

```bash
bash scripts/collect-external-evidence.sh .
# or manually:
prowler aws -M json -o evidence/prowler/
trivy fs --format json --output evidence/trivy/report.json .
osv-scanner --format json --output evidence/osv/report.json -r .
hipaa-audit scan .
```

Controls `HIPAA-INT-001`, `HIPAA-AI-001`, and `HIPAA-STATE-001` ingest scanner output,
check evidence freshness, and prompt for AI/state-law registers when configured.

Browse the wider OSS landscape:

```bash
hipaa-audit sources
```

See [oss-ecosystem.md](oss-ecosystem.md) for Prowler, Checkov, ComplianceKit, SRA tools, and more.

## Annual HIPAA workflow

1. **Q1:** Complete SRA (`templates/sra-template.md`)
2. **Ongoing:** Weekly `hipaa-audit scan` in CI
3. **Quarterly:** Access review + vendor register update
4. **Annual:** Tabletop IR exercise, policy review, workforce training
