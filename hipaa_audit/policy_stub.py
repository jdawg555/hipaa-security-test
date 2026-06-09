"""Helper to generate policy boilerplate — used by init, not runtime."""

POLICY_HEADER = """# {title}

**Status:** Draft v1.0 — customize before adoption
**Owner:** [Security Officer name]
**Review cadence:** Annual + after material change
**Last reviewed:** [DATE]

> Starter template from [hipaa-security-test](https://github.com/jdawg555/hipaa-security-test).
> Not legal advice. Have counsel review before production use.

## 1. Purpose

{purpose}

## 2. Scope

All workforce members, contractors, and systems that create, receive, maintain, or transmit ePHI on behalf of [Organization Name].

## 3. Policy statements

{statements}

## 4. Roles and responsibilities

| Role | Responsibility |
|------|----------------|
| Security Officer | Owns this policy; annual review |
| Privacy Officer | Coordinates with Security on PHI incidents |
| Engineering | Implements technical controls |
| Workforce | Comply with training and acceptable use |

## 5. Exceptions

Exceptions require written approval from the Security Officer and Privacy Officer. Document in the risk register.

## 6. Enforcement

Violations may result in disciplinary action up to termination and regulatory notification where required.

## 7. Related documents

- templates/sra-template.md
- templates/baa-register.md
- policies/incident-response-plan.md
"""
