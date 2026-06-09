# hipaa-audit

> **Self-hosted HIPAA compliance workspace** — use it like Vanta or Drata, without the subscription.

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Version: 2.0](https://img.shields.io/badge/Version-2.0-blue.svg)](CHANGELOG.md)

Open your browser. Connect integrations. Run monitoring scans. Track vendors, access reviews, and personnel. Publish trust center and auditor portals.

**MIT licensed · runs on your machine or Docker · your data stays in your repo**

---

## Start in 60 seconds

```bash
pip install "hipaa-audit[serve,aws,github]"
mkdir ~/my-compliance && cd ~/my-compliance
hipaa-audit serve .
```

Opens **http://127.0.0.1:8787** — onboarding wizard → integrations → run scan.

Or with Docker:

```bash
git clone https://github.com/jdawg555/hipaa-security-test.git
cd hipaa-security-test
docker compose up
# → http://localhost:8787  (data in ./workspace-data/)
```

**Full guide:** [docs/how-to-use-this.md](docs/how-to-use-this.md)

---

## What you get (mapped to Vanta / Drata)

| Vanta / Drata | hipaa-audit workspace |
|---------------|---------------------|
| Dashboard | Posture score, pass/fail, open tasks |
| Integrations | Toggle AWS, GitHub, Okta, Google, Prowler, personnel, vendors… |
| Continuous tests | Run scan on demand or auto-scan every N hours |
| Personnel | Policy acks + training CSV |
| Vendors | Risk register + questionnaire portal |
| Access reviews | Quarterly campaign tracker |
| Devices | Jamf/Intune CSV import |
| Policies | 12 HIPAA policy templates |
| Trust Center | Auto-published after each scan |
| Auditor portal | Read-only evidence + ZIP export |
| HIPAA + SOC 2 + ISO 27001 | Optional framework supplements |

---

## Who this is for

- Healthcare startups needing **HIPAA Security Rule** discipline for enterprise customers
- Teams that want **Vanta-like workflow** but can run a local server or Docker
- Engineering-led security (comfortable with env vars for AWS/GitHub/Okta tokens)

## Who should still pay for Vanta/Drata

- Need 300+ one-click SaaS integrations
- Need MDM laptop agents (not CSV export)
- Need HRIS-driven onboarding and non-technical compliance hires only

---

## CLI (CI & power users)

The workspace uses the same engine:

```bash
hipaa-audit scan .
hipaa-audit export auditor
bash scripts/run-e2e.sh .
```

---

## License

[MIT](LICENSE) — see [NOTICE](NOTICE). Not legal advice; policies require counsel review.
