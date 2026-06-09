# Changelog

## [2.3.0] — 2026-05-28

### Phase 2 — Connection layer

- **Connection wizard** — `/integrations/connect/{id}` saves credentials to gitignored `compliance/.workspace-secrets.yaml` and tests connection
- **Integration health dashboard** — enabled integrations with connection status on the main dashboard
- **Default 24h auto-scan** — onboarding sets `workspace.schedule_hours: 24`
- **Slack settings in workspace** — enable alerts, webhook, score-drop threshold in Settings

### Phase 3 — Workflow UI

- **Vendor CRUD** — add, edit, delete vendors in the workspace
- **BAA register** — structured `compliance/baas.yaml` with `/baas` page and expiry assessment
- **SaaS inventory UI** — `/saas` discover from Okta/Google and link apps to vendors
- **Policy web editor** — edit markdown policies in the browser
- **Posture trend chart** — bar chart on dashboard from scan history
- **Personnel summary** — ack and training counts on Personnel page

## [2.2.0] — 2026-05-28

### Added

- **Integration connection tests** — Test button on Integrations page with connected/failed badges (AWS, GitHub, Okta, Google, Jamf, register-based modules)
- **Tasks workspace page** — `/tasks` with owner assignment and mark-done workflow
- **Access review campaign builder** — start campaigns, record decisions, and complete from the UI
- **Jamf Pro adapter** — `test_connection()` via Jamf Pro API or Classic API fallback
- **Adapter registry** — `hipaa_audit/platform/adapters/registry.py` dispatches connection tests

## [2.1.0] — 2026-05-28

### Added

- **Parity roadmap** — `docs/roadmap/PARITY.md` gap matrix vs Vanta/Drata (30 capabilities, 6 phases)
- **Extension model** — `docs/architecture/EXTENSION_MODEL.md` five-layer build pattern
- **Platform registry** — `platform/capabilities.yaml`, `platform/integrations_registry.yaml`
- **`hipaa-audit parity`** — live gap matrix and coverage estimate
- **`hipaa-audit scaffold`** — `module` and `integration` code generators
- **Adapter SDK** — `hipaa_audit/platform/adapters/base.py` for new connectors

## [2.0.0] — 2026-05-28

### Product: self-hosted compliance workspace

hipaa-audit is now primarily used via **`hipaa-audit serve`** — a local web UI modeled on Vanta/Drata:

- **Dashboard** — posture, tasks, run scan
- **Integrations** — toggle AWS, GitHub, Okta, personnel, vendors, etc.
- **Monitoring** — full control list with status
- **Personnel, Vendors, Access reviews, Devices, Policies**
- **Audits & trust** — trust center, auditor portal, ZIP export
- **Onboarding wizard** — bootstrap policies and registers in 2 minutes
- **Auto-scan scheduler** — configurable interval in Settings
- **Docker Compose** — `docker compose up` on port 8787

### Added

- `hipaa_audit/workspace/` — FastAPI server + Vanta-style navigation
- `hipaa-audit serve` and `hipaa-audit up`
- `docs/how-to-use-this.md` — operator guide
- `Dockerfile`, `docker-compose.yml`

### Changed

- README repositioned: workspace first, CLI second
- Scans from UI sync tasks and refresh trust/auditor portals

## [1.9.0] — 2026-05-28

### Added

- **ISO 27001 supplement** — 10 Annex A controls via `frameworks.iso27001: true`
- **Auditor portal** — `hipaa-audit auditor publish` with optional passphrase gate
- **Vendor questionnaire portal** — `hipaa-audit vendor portal` + `import-response`
- **CLI** — `hipaa-audit framework iso27001`

### Changed

- Framework reports exclude supplemental controls from HIPAA count
- Docs updated for auditor and vendor portals

## [1.8.0] — 2026-05-28

### Added

- **SOC 2 TSC supplement** — 12 controls via `frameworks.soc2: true` + `hipaa-audit framework soc2`
- **MDM device inventory** — `hipaa-audit devices import|list|template` (Jamf/Intune CSV)
- **Vendor questionnaire workflow** — `hipaa-audit vendor send|respond|questionnaires`
- **Google Workspace apps** — API discovery + `apps import-google` CSV in `apps discover`
- **Controls** — `device-inventory-compliant`, `vendor-questionnaires-tracked`
- **Docs** — `docs/frameworks.md`

### Changed

- `load_controls()` merges `soc2-*.yaml` when SOC 2 framework enabled
- `apps discover` pulls Okta and Google when both identity providers enabled

## [1.7.0] — 2026-05-28

### Added

- **Trust center** — `hipaa-audit trust publish` → `compliance/trust-center/index.html`
- **Auditor bundle** — `hipaa-audit export auditor` ZIP for NDA evidence sharing
- **SaaS inventory** — Okta app discovery via `hipaa-audit apps discover|list|link`
- **Control** — `saas-inventory-tracked` (§164.308(a)(4))
- **Examples** — `certifications.example.yaml`, `saas-inventory.example.yaml`
- **Docs** — `docs/trust-center.md`

### Changed

- `hipaa-audit init` copies certifications and SaaS inventory templates
- E2E script publishes trust center and auditor bundle

## [1.6.0] — 2026-05-28

### Added

- **Vendor module** — `compliance/vendors.yaml` SIG-lite questionnaire register
- **`hipaa-audit vendor`** — `init|add|list|review` for PHI vendor risk tracking
- **Access review campaigns** — `compliance/access-reviews.yaml` quarterly SaaS/IAM reviews
- **`hipaa-audit access-review`** — `start|list|decide|complete` campaign workflow
- **Controls** — `vendor-register-current` (§164.308(b)(1)), `access-review-campaign` (§164.308(a)(4))
- **Template** — `templates/vendor-questionnaire.md`
- **Docs** — `docs/vendor-access-reviews.md`

### Changed

- `hipaa-audit init` copies vendor and access-review example registers
- E2E script includes vendor + access-review CLI smoke steps

## [1.5.0] — 2026-05-28

### Added

- **Probo HIPAA catalog** — 60 CFR specs via `controls/probo-hipaa-catalog.json` + 48 supplement controls (100% coverage)
- **`hipaa-audit catalog coverage`** — crosswalk report vs Probo
- **Personnel module** — policy acknowledgments YAML + training CSV checks
- **`hipaa-audit import-training`** — bootstrap `compliance/training-log.csv`
- **Slack notifications** — `--notify` or `notifications.slack` on posture drop / failures
- **Examples** — `compliance/acknowledgments.example.yaml`

### Changed

- `load_controls()` merges all `controls/hipaa-*.yaml` catalogs (76+ controls total)
- E2E script includes catalog coverage step

## [1.4.0] — 2026-05-28

### Added

- **14 new AWS checks** — IAM root MFA, password policy, VPC flow logs, S3 encryption, RDS backup, Security Hub, Config, CloudTrail validation, EBS default encryption
- **Identity module** — Okta MFA policies, inactive users; Google Workspace 2SV (optional `[identity]` extra)
- **Posture engine** — weighted score, `evidence/history/posture.jsonl` trend, dashboard display
- **Remediation tasks** — `compliance/tasks.yaml`, `hipaa-audit tasks list|sync|done`, auto-sync on scan
- **Probo export** — `hipaa-audit export probo` for getprobo/probo GRC import
- **E2E script** — `scripts/run-e2e.sh` full workflow
- **Docs** — `docs/stacks/probo-hipaa-audit.md`
- **Controls** — `HIPAA-AWS-002`, `HIPAA-AWS-003`, `HIPAA-IDP-001` (29 controls total)

### Changed

- Dashboard shows posture score, open tasks, history trend
- `hipaa-audit init` copies tasks template and e2e script

## [1.3.0] — 2026-05-28

### Added

- **`hipaa-audit import-sra`** — merge l0lsec/hipaa-sra or SaberGuard browser JSON into `templates/sra-imported.md`
- **ComplianceKit ingest** — `integrations.compliancekit` reads `control-mapping.csv` HIPAA rows
- **Controls:** `compliancekit-mapping`, `sra-json-import` on SRA / INT groups
- **Fixtures + tests** for SRA import and ComplianceKit CSV parsing

### Changed

- `sra-documented` check accepts `templates/sra-imported.md`
- OSS catalog marks ComplianceKit as integrated

## [1.2.0] — 2026-05-28

### Added

- **Checkov integration** — ingest IaC scan JSON (`integrations.checkov`)
- **`hipaa-audit sources`** — curated OSS catalog (`integrations/oss-catalog.yaml`)
- **Docs:** `docs/oss-ecosystem.md`, `docs/crosswalks/prowler-hipaa-aws.md`
- **Examples:** `examples/terraform-minimal/` for Checkov demos
- **Scripts:** `install-optional-scanners.sh`; Prowler `--compliance hipaa_aws` in collector
- **CI:** Trivy + OSV-Scanner + Checkov evidence steps in GitHub Actions
- **`.checkov.example.yaml`** — HIPAA-oriented IaC check list

### Changed

- Wheel build bundles `controls/`, `policies/`, `templates/`, `integrations/` for pip installs

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
