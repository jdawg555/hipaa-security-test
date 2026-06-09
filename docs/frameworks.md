# Multi-framework support (SOC 2)

v1.8 adds an optional **SOC 2 TSC supplement** alongside the HIPAA catalog.

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
