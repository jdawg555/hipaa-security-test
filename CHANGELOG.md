# Changelog

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
