# HIPAA Security Policy

**Status:** Draft v1.0 — customize before adoption  
**Owner:** [Security Officer]  
**Review cadence:** Annual + after material change  
**Last reviewed:** [DATE]

## 1. Purpose

Establish administrative, physical, and technical safeguards for electronic Protected Health Information (ePHI) per 45 CFR Part 164 Subpart C.

## 2. Scope

All systems, workforce, and business associates that handle ePHI for [Organization Name].

## 3. Security Officer

[Name, title, contact] is designated Security Official per §164.308(a)(2).

## 4. Required safeguards

| Safeguard area | Implementation |
|----------------|----------------|
| Risk management | Annual SRA (`templates/sra-template.md`) + continuous `hipaa-audit scan` |
| Access control | Unique IDs, MFA, least privilege, quarterly access review |
| Audit controls | Immutable logs, 6-year retention, quarterly review |
| Integrity | Code review, CI security gates, dependency pinning |
| Transmission | TLS 1.2+ everywhere PHI crosses a network |
| Encryption at rest | AES-256 or equivalent on all PHI stores |
| Incident response | `policies/incident-response-plan.md`, 60-day breach assessment |
| Contingency | Daily backups, annual restore test, documented RTO/RPO |
| Workforce | Annual HIPAA training, signed acceptable use |
| Vendors | BAA before PHI flows (`templates/baa-register.md`) |

## 5. Review

Security Officer reviews this policy annually and after any Sev 1/2 incident or material architecture change.
