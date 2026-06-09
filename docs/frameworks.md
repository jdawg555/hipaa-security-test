# Multi-framework support (SOC 2 + ISO 27001)

v1.8+ adds optional **SOC 2** and **ISO 27001** supplements alongside HIPAA.

## Enable SOC 2

```yaml
frameworks:
  hipaa: true
  soc2: true
```

```bash
hipaa-audit framework soc2
hipaa-audit scan .   # includes SOC2-* controls (12 additional)
```

SOC 2 controls reuse the same check modules (AWS, GitHub, vendors, devices, access reviews) — no duplicate scanner logic.

## SOC 2 control map

| Control | TSC | Shared checks |
|---------|-----|---------------|
| SOC2-CC6.1 | Logical access | Access reviews, SaaS inventory |
| SOC2-CC6.7 | Endpoints | MDM device inventory |
| SOC2-CC9.2 | Vendor risk | Vendor register + questionnaires |
| SOC2-CC7.2 | Monitoring | CloudTrail, scanner evidence freshness |

Catalog: `controls/soc2-tsc-supplement.yaml`

## ISO 27001 Annex A

```yaml
frameworks:
  iso27001: true
```

```bash
hipaa-audit framework iso27001
hipaa-audit scan .
```

10 Annex A controls (A.5.1, A.5.15, A.5.23, A.5.29, A.8.1, A.8.2, A.8.5, A.8.9, A.8.15, A.8.24) reuse shared checks.

Catalog: `controls/iso27001-supplement.yaml`

## Auditor portal

```bash
export AUDITOR_PORTAL_PASSPHRASE='your-nda-passphrase'
hipaa-audit scan .
hipaa-audit auditor publish
open compliance/auditor-portal/index.html
```

Read-only portal with optional client-side passphrase gate. Pair with `hipaa-audit export auditor` for ZIP evidence.

## Vendor questionnaire portal

```bash
hipaa-audit vendor send VND-002 security-vendor@example.com
hipaa-audit vendor portal QNR-001
# vendor completes form → downloads QNR-001-response.yaml
hipaa-audit vendor import-response QNR-001 QNR-001-response.yaml
```

## MDM devices

```bash
hipaa-audit devices template
hipaa-audit devices import jamf-export.csv
hipaa-audit devices list
```

Enable `devices.enabled: true` for scan check on §164.310(d)(1).

## Vendor questionnaire workflow

```bash
hipaa-audit vendor send VND-002 security-vendor@example.com
hipaa-audit vendor respond QNR-001 --reviewer security@your-org.com
hipaa-audit vendor questionnaires
```

## Google Workspace app discovery

```bash
# API (requires identity.google + Admin Reports scope)
hipaa-audit apps discover

# Or CSV from Admin Console → Security → API controls
hipaa-audit apps import-google google-apps.csv
```
