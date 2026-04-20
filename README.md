# HIPAA Security Risk Assessment Template

> A free, opinionated, **first-cut** SRA template for healthcare teams bringing PHI online.
> Adapted from the actual one we use for [Luxon Sync](https://luxonmedical.com).

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Version: 0.1](https://img.shields.io/badge/Version-0.1-blue.svg)](CHANGELOG.md)
[![Maintained by Luxon Medical](https://img.shields.io/badge/Maintained%20by-Luxon%20Medical-0c6e7c.svg)](https://luxonmedical.com/ai)

---

## What this is

A **starting skeleton** for a HIPAA Security Risk Assessment, stripped of Luxon-specific
content and intentionally short. Use it to:

- Get a draft SRA in front of your team in an afternoon, not a quarter.
- Stop paying $5–10k for a generic template you'll have to rewrite anyway.
- Have an honest conversation with your privacy officer about what's actually in scope.

**This is not a finished assessment.** Real SRAs need engineering input, business
context, and a privacy/security officer's sign-off.

---

## What this is NOT

- ❌ A substitute for legal counsel
- ❌ A substitute for a real Security Risk Assessment when you have PHI in production
- ❌ Coverage of state-law overlays (CCPA, TX HB 300, NY SHIELD, WA My Health My Data)
- ❌ AI-specific risk modeling (model drift, training data provenance, prompt injection)

For any of the above — or for help filling this in for a real system —
[Luxon AI](https://luxonmedical.com/ai) does HIPAA + AI Implementation Audits in 2 weeks.

---

## How to use it

1. **Fork or download** [`sra-template.md`](sra-template.md).
2. Drop it into your repo at `docs/security/sra.md` (or wherever your team keeps governance docs).
3. Walk through every section in order. Where you don't have an answer yet, write **TBD** —
   never lie or skip silently.
4. Have your **engineering lead**, **security officer**, and **one operational owner** review
   and sign section 8 before you call it done.
5. Re-review at least every **12 months** or after any material change to the system,
   vendors, or data flows.

---

## What's in it

- **Scope & system description** — what's covered, what isn't
- **Data inventory** — PHI, sensitive non-PHI, and explicitly-excluded data
- **Data flow & locations** — at rest, in transit, third parties
- **Access controls** — IdP, MFA, roles, joiner/mover/leaver, break-glass
- **Audit logging** — what's logged, who reads it, tamper-evidence
- **Threats & vulnerabilities** — likelihood × impact ratings, residual risk
- **Incident response** — named commander, 60-day breach clock, tabletop cadence
- **Sign-off** — accountability with names + dates

Plus an honest appendix on what the template intentionally leaves out.

---

## Why we made this public

Most healthcare consultants treat their SRA template as secret sauce.
We don't, because:

1. **The template isn't the work.** The work is interpreting it for *your* system.
2. **Public artifacts build trust faster than logos.** This document is a free
   demonstration of how we think.
3. **Healthcare AI is moving too fast for everyone to learn HIPAA the hard way.**
   If 100 teams use this and 5 of them don't ship a HIPAA incident next year, that's
   a win for patients.

---

## Versioning

- **v0.1 — April 2026.** First public cut. Expect breaking changes.
- See [CHANGELOG.md](CHANGELOG.md) for revision history.

Future versions will add:

- AI-specific risk rows (model drift, prompt injection, training-data provenance, clinician override)
- State privacy law overlay appendix
- Vendor risk register companion template
- A YAML / JSON variant for teams that want machine-parseable controls

---

## Contributing

Improvements welcome — open an issue or PR. We're especially interested in:

- Wording that proves false in real audits
- Additional threat rows from incidents you've seen
- State-law appendices contributed by counsel in those states
- Cleaner Markdown / table layout

If you're contributing on behalf of an organization, mention it in the PR — we'll
credit it in `CHANGELOG.md`.

---

## License

[MIT](LICENSE) — fork, adapt, sell, sublicense. No attribution required, but appreciated.

---

## About

This template is maintained by **[Luxon Medical](https://luxonmedical.com)**, the team behind:

- **[Luxon Sync](https://luxonmedical.com/asc-logistics)** — ASC case-readiness platform with an
  executed Google Cloud BAA, AI-assisted intake on real PHI, role-based access, and live OR orchestration.
- **[Luxon AI](https://luxonmedical.com/ai)** — HIPAA + AI Implementation Audits for healthcare
  operators and medtech AI vendors. Founding cohort pricing through 2026.

Questions: **luxonmed@gmail.com**
