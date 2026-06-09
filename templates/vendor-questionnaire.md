# Vendor Security Questionnaire (SIG-lite)

Use for PHI-touching vendors. Record answers in `compliance/vendors.yaml` via `hipaa-audit vendor review`.

| # | Question | Response (Y/N) | Evidence |
|---|----------|----------------|----------|
| 1 | SOC 2 Type II or ISO 27001 certification current? | | |
| 2 | Encryption at rest for PHI? | | |
| 3 | Encryption in transit (TLS 1.2+)? | | |
| 4 | MFA enforced for admin access? | | |
| 5 | Access logging and retention ≥ 1 year? | | |
| 6 | Incident notification within 24–72 hours? | | |
| 7 | Subprocessors list provided and reviewed? | | |
| 8 | Data retention and deletion policy documented? | | |

**Reviewer:** ___________ **Date:** ___________

Map to YAML keys: `soc2_or_iso`, `encryption_at_rest`, `encryption_in_transit`, `mfa_enforced`, `access_logging`, `incident_notification`, `subprocessors_disclosed`, `data_retention_defined`.
