# Open-source HIPAA compliance ecosystem

**hipaa-audit** is the orchestration layer — controls, policies, evidence export, and CI.
Pair it with best-in-class OSS scanners rather than reinventing cloud posture tools.

Run `hipaa-audit sources` for the curated catalog (`integrations/oss-catalog.yaml`).

## Recommended stack (100% OSS)

| Layer | Tool | License | hipaa-audit integration |
|-------|------|---------|-------------------------|
| Controls + dashboard | **hipaa-audit** | MIT | — |
| AWS HIPAA mode | [Prowler](https://github.com/prowler-cloud/prowler) | Apache-2.0 | `integrations.prowler` |
| IaC HIPAA checks | [Checkov](https://github.com/bridgecrewio/checkov) | Apache-2.0 | `integrations.checkov` |
| CVE scan | [Trivy](https://github.com/aquasecurity/trivy) | Apache-2.0 | `integrations.trivy` |
| Dependency CVEs | [OSV-Scanner](https://github.com/google/osv-scanner) | Apache-2.0 | `integrations.osv` |
| SQL cloud inventory | [Steampipe](https://github.com/turbot/steampipe) | AGPL | Manual export |
| IR plan starter | [Counteractive template](https://github.com/counteractive/incident-response-template) | MIT | Copy into `policies/` |

## One-command evidence collection

```bash
bash scripts/collect-external-evidence.sh /path/to/your-repo
hipaa-audit scan /path/to/your-repo
```

Install optional scanners: `bash scripts/install-optional-scanners.sh`

## Prowler HIPAA crosswalk

Prowler ships `hipaa_aws.json` with 32 requirements and 85+ checks mapped to
§164.308 and §164.312. See [crosswalks/prowler-hipaa-aws.md](crosswalks/prowler-hipaa-aws.md).

```bash
prowler aws --compliance hipaa_aws -M json -o evidence/prowler/
```

## Full GRC platforms (reference only)

These are **not** dependencies — useful for feature comparison and gap analysis:

| Project | License | Notes |
|---------|---------|-------|
| [ComplianceKit](https://github.com/darpanzope/compliancekit) | Apache-2.0 | 50 HIPAA specs, evidence CSV |
| [ControlWeave](https://github.com/sherifconteh-collab/ControlWeave) | AGPL-3.0 | Multi-framework auditor workspace |
| [TrustOS](https://github.com/Backboard-io/TrustOS) | Mixed | SOC2 + HIPAA automation |
| [Shasta](https://github.com/transilienceai/shasta) | Check repo | AWS/Azure HIPAA checks + dashboard |

hipaa-audit stays **MIT**, git-native, and scanner-agnostic — no AGPL runtime deps.

## SRA tooling

| Tool | Type | When to use |
|------|------|-------------|
| `templates/sra-template.md` | Markdown in git | Default for hipaa-audit adopters |
| [SaberGuard HIPAA-SRA-Tool](https://github.com/SaberGuard-LLC/HIPAA-SRA-Tool) | Browser MIT | Interactive checklist + PDF |
| [l0lsec/hipaa-sra](https://github.com/l0lsec/hipaa-sra) | Self-hosted MIT | 33 controls + policy library |
| [HHS ONC SRA Tool](https://www.healthit.gov/privacy-security/security-risk-assessment-tool) | Windows desktop | OCR-aligned official wizard |

## Policy template licenses

- **hipaa-audit `policies/`** — MIT, generic placeholders
- **JupiterOne templates** — CC-BY-SA-4.0 if you borrow wording (attribute + share-alike)
- **Counteractive IR** — MIT, safe to fork

## CI pattern

The bundled [compliance-audit.yml](../.github/workflows/compliance-audit.yml) runs:

1. Trivy filesystem scan → `evidence/trivy/`
2. OSV-Scanner → `evidence/osv/`
3. Checkov on `examples/terraform-minimal/` → `evidence/checkov/`
4. `hipaa-audit scan` with integrations enabled

AWS Prowler stays optional (requires cloud credentials in your pipeline).
