# Evidence directory

`hipaa-audit scan` writes timestamped artifacts here:

- `audit-report.json` — machine-readable for CI and auditors
- `audit-report.md` — human-readable summary
- `dashboard.html` — Vanta-style compliance dashboard (open locally)
- `secret-scan.json`, `aws-*.json`, etc. — per-check evidence

**Do not commit real PHI or production credentials.** Add `evidence/` to `.gitignore` in your application repo; upload artifacts to your secure compliance drive or GRC tool.
