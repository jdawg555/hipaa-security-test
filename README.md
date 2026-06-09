# hipaa-audit

> **Free, open-source HIPAA compliance platform** — Vanta/Drata-style continuous monitoring, control mapping, policy library, and evidence collection. **$0 forever.**

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Version: 1.0](https://img.shields.io/badge/Version-1.0-blue.svg)](CHANGELOG.md)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](pyproject.toml)

Built by [Luxon Medical](https://luxonmedical.com) for healthcare teams who need HIPAA Security Rule compliance without a $10k/yr GRC subscription.

---

## What this is

A **complete HIPAA compliance toolkit** in one repo:

| Component | Description |
|-----------|-------------|
| **`hipaa-audit` CLI** | Scan your repo + cloud for 25+ HIPAA Security Rule controls |
| **Control catalog** | `controls/hipaa-security-rule.yaml` — §164.308/310/312 mapped to checks |
| **12 policy templates** | Privacy, security, access, IR, breach, encryption, vendors, training… |
| **SRA + registers** | Risk assessment, BAA register, vendor risk register |
| **HTML dashboard** | Open `evidence/latest/dashboard.html` — pass/fail by control |
| **GitHub Actions** | Weekly continuous monitoring + PR gate |
| **AWS + GitHub checks** | CloudTrail, S3, RDS, KMS, branch protection, secret scanning |

```bash
pip install git+https://github.com/jdawg555/hipaa-security-test.git
hipaa-audit init          # bootstrap your app repo
hipaa-audit scan .        # run all checks
open evidence/latest/dashboard.html
```

---

## Quick start

```bash
# Clone and install
git clone https://github.com/jdawg555/hipaa-security-test.git
cd hipaa-security-test
pip install -e ".[aws,github]"

# Self-audit (this repo audits itself)
hipaa-audit scan .

# Bootstrap your healthcare application
cd /path/to/your-app
hipaa-audit init
# Edit hipaa-audit.yaml + customize policies/
hipaa-audit scan .
```

See [docs/getting-started.md](docs/getting-started.md) for AWS/GitHub setup.

---

## Architecture

```
hipaa-security-test/
├── hipaa_audit/           # Python CLI + check engine
│   └── checks/            # repo, aws, github, policies modules
├── controls/              # HIPAA control catalog (YAML)
├── policies/              # 12 customizable policy templates
├── templates/             # SRA, risk register, BAA register
├── evidence/              # Scan output (gitignored in your app)
└── .github/workflows/     # Continuous compliance CI
```

**Check flow:** `hipaa-audit scan` → load controls → run automated checks → collect evidence JSON → generate dashboard + audit report.

---

## Control coverage

| HIPAA area | Controls | Automated |
|------------|----------|-----------|
| Administrative (§164.308) | Risk analysis, workforce, access, training, IR, BAA | Partial |
| Physical (§164.310) | Facility, device/media | Manual |
| Technical (§164.312) | Access, audit, integrity, authentication, transmission | **Yes** |
| Documentation (§164.316) | Policy library, review cadence | **Yes** |
| Developer hygiene | Secrets, PHI in repo, lockfiles, CI gates | **Yes** |
| AWS hardening | CloudTrail, S3, RDS, KMS, GuardDuty | **Yes** (optional) |

List all controls: `hipaa-audit controls`

---

## vs Vanta / Drata

| | Vanta/Drata | hipaa-audit |
|---|-------------|-------------|
| Cost | ~$10–15k/yr | **Free (MIT)** |
| HIPAA controls | ✅ | ✅ |
| Evidence export | ✅ | ✅ JSON + HTML |
| AWS monitoring | ✅ | ✅ (Prowler-compatible) |
| Policy templates | ✅ | ✅ |
| Personnel/device agents | ✅ | ❌ (manual) |
| Auditor trust center | ✅ | HTML dashboard |
| Self-hosted / git-native | ❌ | ✅ |

Full comparison: [docs/vanta-comparison.md](docs/vanta-comparison.md)

Pair with **[Prowler](https://github.com/prowler-cloud/prowler)** + **[Trivy](https://github.com/aquasecurity/trivy)** for enterprise-grade evidence at zero license cost.

---

## Configuration

Copy `hipaa-audit.example.yaml` → `hipaa-audit.yaml`:

```yaml
org_name: "Acme Health"
aws:
  enabled: true
  region: us-east-1
github:
  enabled: true
  repo: acme-health/platform
```

---

## What this is NOT

- ❌ Legal advice or a substitute for counsel
- ❌ A finished Security Risk Assessment (use `templates/sra-template.md`)
- ❌ SOC 2 / HITRUST certification (HIPAA-focused; mappings are informative)
- ❌ Laptop MDM or workforce training tracking (manual attestation)

---

## Contributing

PRs welcome — especially:

- New check modules (Azure, GCP, Okta, Telnyx…)
- State privacy law overlays (CCPA, TX HB 300, WA My Health My Data)
- Prowler/Trivy evidence ingestion
- AI-specific risk rows (model drift, prompt injection)

---

## License

[MIT](LICENSE) — use commercially, fork freely.

Maintained by **[Luxon Medical](https://luxonmedical.com)** · Questions: luxonmed@gmail.com
