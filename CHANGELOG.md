# Changelog

## [1.1.0] — 2026-05-28

### Added

- **Integrations module** — ingest Prowler, Trivy, and OSV-Scanner JSON evidence
- **Controls:** `HIPAA-INT-001` (scanner evidence), `HIPAA-AI-001`, `HIPAA-STATE-001`
- **Templates:** `ai-risk-register.md`, `state-law-overlay.md`, `workforce-training-log.md`
- **OSS docs:** `CONTRIBUTING.md`, `NOTICE.md`, `SECURITY.md` (MIT template guidelines)
- **Script:** `scripts/collect-external-evidence.sh` for optional scanner collection
- **Tests:** integration check handlers

### Changed

- **MIT license** — generic `hipaa-audit contributors` copyright; org-specific branding removed
- **SRA template** — neutral placeholders only
- **`hipaa-audit init`** — copies evidence collection script
- **Config example** — `integrations` block with freshness, AI register, state overlay

## [1.0.0] — 2026-06-09

### Added — full open-source HIPAA compliance platform

- **`hipaa-audit` CLI** — `scan`, `init`, `controls`, `version` commands
- **25+ HIPAA Security Rule controls** in `controls/hipaa-security-rule.yaml`
- **Automated checks:** repo secrets/PHI scan, policy library, AWS (CloudTrail, S3, RDS, KMS, GuardDuty), GitHub (branch protection, secret scanning, Dependabot)
- **12 policy templates** in `policies/`
- **Registers:** SRA, risk register, BAA register, vendor risk register in `templates/`
- **Evidence export:** JSON, Markdown, HTML dashboard
- **GitHub Actions** weekly compliance workflow
- **Docs:** getting started, Vanta/Drata comparison
- **Tests:** control catalog + self-audit integration test

### Changed

- Repo renamed scope: from SRA-only template → holistic GRC toolkit
- `sra-template.md` moved to `templates/sra-template.md` (root copy retained for backward links)

## [0.1] — 2026-04-19

- Initial SRA Markdown template only
