# hipaa-audit + Probo stack

[Probo](https://github.com/getprobo/probo) is a self-hosted GRC platform (trust center, vendors, access reviews).
**hipaa-audit** is the technical evidence engine. Use both for Vanta/Drata-style coverage at $0.

## Architecture

```
OSS scanners (Prowler, Checkov, Trivy, ComplianceKit)
        ↓
   hipaa-audit scan  →  posture score, tasks, dashboard
        ↓
   hipaa-audit export probo  →  probo-import.json
        ↓
   Probo (measures, evidence, compliance page)
```

## Quick start

### 1. Technical monitoring (hipaa-audit)

```bash
pip install git+https://github.com/jdawg555/hipaa-security-test.git@v1.4.0
hipaa-audit init
bash scripts/run-e2e.sh .
```

### 2. GRC platform (Probo)

```bash
git clone --recurse-submodules https://github.com/getprobo/probo.git
cd probo && make stack-up && make build && make dev-config
bin/probod -cfg-file cfg/dev.yaml
# Console: http://localhost:8080
```

### 3. Import hipaa-audit evidence

```bash
hipaa-audit export probo -o evidence/latest/probo-import.json
```

Use Probo CLI or MCP to create measures from `measures[]` in the export:

```bash
prb auth login
# For each failing measure, create evidence and link to control
prb measure create --name "S3 public access block"
prb evidence create --measure <id> --file evidence/latest/aws-s3-public-access.json
```

Or connect an MCP agent to Probo and pass `probo-import.json` for bulk import.

## When to use which

| Need | Tool |
|------|------|
| AWS/Okta/GitHub automated checks | hipaa-audit |
| Posture score + remediation tasks | hipaa-audit |
| Policy sign-off, vendor risk, trust page | Probo |
| Auditor PBC / compliance portal | Probo |

## Configuration

Enable cloud + identity in `hipaa-audit.yaml`:

```yaml
aws:
  enabled: true
  region: us-east-1
identity:
  okta:
    enabled: true
    domain: your-org.okta.com
  google:
    enabled: false
```

Set `OKTA_API_TOKEN` in CI or locally (never commit).
