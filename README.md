# hipaa-audit

> **Free, open-source HIPAA compliance toolkit** — continuous monitoring, control mapping,
> policy library, and evidence collection. MIT licensed. No subscription.

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Version: 1.4](https://img.shields.io/badge/Version-1.4-blue.svg)](CHANGELOG.md)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](pyproject.toml)

A community-maintained alternative to paid GRC platforms (Vanta, Drata, etc.) for teams
subject to the **HIPAA Security Rule** (45 CFR Part 164 Subpart C).

---

## Features

| Component | Description |
|-----------|-------------|
| **`hipaa-audit` CLI** | Scan repo + AWS + Okta/Google for 29 controls / 55+ checks |
| **Posture score** | Weighted compliance % + history trend |
| **Remediation tasks** | Auto-sync failures → `compliance/tasks.yaml` |
| **Probo export** | `hipaa-audit export probo` for full GRC stack |
| **Control catalog** | `controls/hipaa-security-rule.yaml` with CFR citations |
| **12 policy templates** | Privacy, security, access, IR, breach, encryption, vendors… |
| **Registers** | SRA, risk, BAA, vendor risk, **AI risk**, **state law overlay** |
| **Integrations** | Ingest **Prowler**, **Checkov**, **Trivy**, **OSV-Scanner** evidence |
| **OSS catalog** | `hipaa-audit sources` — curated GitHub ecosystem |
| **SRA import** | `hipaa-audit import-sra` — browser JSON → Markdown gaps |
| **ComplianceKit** | Ingest `control-mapping.csv` HIPAA findings |
| **HTML dashboard** | Pass/fail dashboard for auditors and security reviews |
| **GitHub Actions** | Weekly compliance workflow |

```bash
pip install git+https://github.com/jdawg555/hipaa-security-test.git
hipaa-audit init && hipaa-audit scan .
hipaa-audit import-sra ~/Downloads/hipaa-sra-export.json
open evidence/latest/dashboard.html
```

---

## Quick start

```bash
git clone https://github.com/jdawg555/hipaa-security-test.git
cd hipaa-security-test
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

hipaa-audit scan .                 # audit this repo
hipaa-audit init                   # bootstrap your app repo
bash scripts/run-e2e.sh .
```

Copy `hipaa-audit.example.yaml` → `hipaa-audit.yaml` and set `org_name`.

Full guide: [docs/getting-started.md](docs/getting-started.md) · OSS stack: [docs/oss-ecosystem.md](docs/oss-ecosystem.md)

---

## Repository layout

```
├── hipaa_audit/          # CLI + check engine
├── controls/             # HIPAA control catalog (YAML)
├── policies/             # Customizable policy templates
├── templates/            # SRA, registers, AI + state overlays
├── scripts/              # External evidence collection helper
└── .github/workflows/    # compliance-audit.yml
```

---

## Configuration (generic)

```yaml
org_name: "Your Organization"

integrations:
  max_evidence_age_days: 7
  prowler:
    enabled: true
    evidence_glob: evidence/prowler/*.json
  trivy:
    enabled: true
    fail_severities: [CRITICAL, HIGH]
  require_ai_register: false   # true if clinical AI in scope
  applicable_states: []        # e.g. [CA, TX, WA] for state overlay

aws:
  enabled: false
  region: us-east-1

github:
  enabled: false
  repo: your-org/your-repo
```

---

## vs paid GRC platforms

| | Vanta / Drata | hipaa-audit |
|---|---------------|-------------|
| License cost | ~$10k+/yr | **$0 (MIT)** |
| HIPAA controls | ✅ | ✅ |
| Evidence export | ✅ | JSON + HTML |
| AWS / code checks | ✅ | ✅ + Prowler/Trivy ingest |
| Personnel MDM | ✅ | Manual attestation templates |
| Self-hosted / git-native | ❌ | ✅ |

See [docs/vanta-comparison.md](docs/vanta-comparison.md)

---

## What this is NOT

- Legal or compliance advice ([NOTICE](NOTICE))
- A substitute for counsel-reviewed policies
- SOC 2 / HITRUST certification
- Workforce MDM or training platform

---

## Contributing

PRs welcome — keep checks **vendor-neutral** and **org-agnostic**.
See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

---

## License

[MIT](LICENSE) — use, modify, sublicense, commercially. See [NOTICE](NOTICE) for disclaimers.
