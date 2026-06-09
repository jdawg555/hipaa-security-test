# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 1.1.x   | Yes       |
| 1.0.x   | Yes       |
| < 1.0   | No        |

## Reporting a vulnerability

If you find a security issue in **hipaa-audit** (not your fork's HIPAA posture):

1. Open a [private security advisory](https://github.com/jdawg555/hipaa-security-test/security/advisories/new) on GitHub, **or**
2. Open an issue with minimal reproduction steps if impact is low (e.g. false-negative in a check)

Please do **not** include real PHI or production credentials in reports.

## Scope

- CLI, check handlers, evidence writer, GitHub Action workflow
- Out of scope: your organization's AWS/GitHub configuration surfaced by scans

## Safe use

- Store `hipaa-audit.yaml` and evidence locally or in a **private** repo
- Do not commit workforce training logs with employee names to public git
- Rotate any credential accidentally flagged by `no_secrets_in_repo`
