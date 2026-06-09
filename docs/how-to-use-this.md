# How to use hipaa-audit (like Vanta / Drata)

hipaa-audit is a **self-hosted compliance workspace**. You run it on your machine or server — not a SaaS login.

## The one command that matters

```bash
pip install "hipaa-audit[serve,aws,github]"
mkdir ~/acme-compliance && cd ~/acme-compliance
hipaa-audit serve .
```

Your browser opens **http://127.0.0.1:8787** — the same mental model as Vanta/Drata:

| Vanta / Drata | hipaa-audit workspace |
|---------------|----------------------|
| Dashboard | **Dashboard** — posture score, pass/fail counts |
| Integrations | **Integrations** — toggle AWS, GitHub, Okta, personnel, vendors… |
| Tests / Monitoring | **Monitoring** — control list; click **Run scan** |
| Personnel | **Personnel** — acks + training files |
| Vendors | **Vendors** — register + questionnaires |
| Access reviews | **Access reviews** — quarterly campaigns |
| Devices | **Devices** — MDM CSV inventory |
| Policies | **Policies** — your markdown library |
| Trust Center + Audits | **Audits & trust** — publish portals + ZIP |
| Settings | **Settings** — org name, frameworks, auto-scan interval |

## Docker (team server)

```bash
git clone https://github.com/jdawg555/hipaa-security-test.git
cd hipaa-security-test
docker compose up
# → http://localhost:8787
# Data persists in ./workspace-data/
```

Add credentials to `docker-compose.yml` environment or a `.env` file.

## First-time setup (onboarding wizard)

1. Open the workspace → enter **organization name**.
2. We copy policies, compliance registers, and CI workflow into your folder.
3. Go to **Integrations** → turn on what you use (AWS, GitHub, Okta…).
4. Add credentials (env vars or Docker env).
5. Click **Run monitoring scan** on the dashboard.
6. Fix failures; re-scan until posture is green enough for your risk appetite.

## Credentials (same as Vanta “Connect AWS”)

| Integration | What you provide |
|-------------|------------------|
| AWS | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, or IAM role |
| GitHub | `GITHUB_TOKEN` + repo slug in Settings |
| Okta | `OKTA_API_TOKEN` + domain in Settings |
| Google | `GOOGLE_APPLICATION_CREDENTIALS` service account |
| Prowler/Trivy | Run `bash scripts/collect-external-evidence.sh` periodically |

## Continuous monitoring

- **Settings → Auto-scan interval** — e.g. `24` hours (like Vanta hourly tests, on your schedule).
- Or use **GitHub Actions** (copied by onboarding) for CI-based scans.

## Customer diligence & audits

After each scan the workspace refreshes:

- **Trust center** — public page for prospects
- **Auditor portal** — read-only control evidence
- **Auditor ZIP** — download from Audits & trust

Set `AUDITOR_PORTAL_PASSPHRASE` before scan for NDA gate (CLI still supported).

## CLI still exists

Power users and CI use the same engine:

```bash
hipaa-audit scan .
hipaa-audit vendor send VND-001 vendor@example.com
```

The workspace is the **default** UX; CLI is for automation.

## When you still need Vanta/Drata

- 300+ click-to-connect integrations
- MDM laptop agents (we use CSV import)
- HRIS-driven onboarding
- Hosted auditor request/response threads

For most seed-stage healthcare startups: **workspace + counsel + Prowler** is enough to pass enterprise security reviews.
