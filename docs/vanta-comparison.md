# How this compares to Vanta / Drata

**Build roadmap:** [roadmap/PARITY.md](roadmap/PARITY.md) · **How to implement:** [architecture/EXTENSION_MODEL.md](architecture/EXTENSION_MODEL.md) · **Live status:** `hipaa-audit parity`

## What paid GRC platforms do well

- Personnel compliance (device agents, training attestations)
- 300+ SaaS integrations out of the box
- Auditor-facing trust center with access controls
- SOC 2 + ISO 27001 + HIPAA in one dashboard
- Vendor questionnaire automation

## What hipaa-audit does (free)

- **HIPAA-first** control catalog with CFR citations
- **Repo-native** — policies and evidence live in git beside your code
- **Automated checks** for AWS, GitHub, secrets, PHI heuristics
- **Self-hosted** — no vendor lock-in, no per-seat pricing
- **Extensible** — add checks in Python; YAML control definitions

## Recommended stack (100% OSS)

| Layer | Tool | License |
|-------|------|---------|
| HIPAA controls + dashboard | **hipaa-audit** (this repo) | MIT |
| AWS config evidence | [Prowler](https://github.com/prowler-cloud/prowler) | Apache 2.0 |
| Vulnerability scan | [Trivy](https://github.com/aquasecurity/trivy) | Apache 2.0 |
| SQL compliance queries | [Steampipe](https://steampipe.io/) | AGPL (tooling only) |
| Policy text starters | [JupiterOne templates](https://github.com/JupiterOne/security-policy-templates) | CC-BY-SA 4.0 |
| IR plan starter | [Counteractive](https://github.com/counteractive/incident-response-template) | MIT |

## When to still pay for Vanta/Drata

- Enterprise customers require a named SOC 2 auditor portal
- You need MDM/laptop compliance without building it
- Compliance team > 2 FTE and integration maintenance is cheaper outsourced

For seed-stage healthcare startups and OSS projects, **hipaa-audit + Prowler + counsel** covers 80% of the value at 0% of the subscription cost.
