# Trust center & auditor portal

v1.7 adds Vanta/Probo-style **public trust pages** and **auditor evidence bundles**.

## Trust center

1. Run a scan and publish:

```bash
hipaa-audit scan .
hipaa-audit trust publish
open compliance/trust-center/index.html
```

2. Configure in `hipaa-audit.yaml`:

```yaml
trust_center:
  output_dir: compliance/trust-center
  contact_email: security@your-org.com
  certifications_path: compliance/certifications.yaml
```

3. List public certifications in `compliance/certifications.yaml` (copy from `certifications.example.yaml`).

Host `compliance/trust-center/` on Cloudflare Pages, S3 static site, or your marketing domain (`trust.your-org.com`).

## Auditor evidence bundle

```bash
hipaa-audit scan .
hipaa-audit export auditor -o evidence/latest/auditor-bundle.zip
```

Includes audit JSON/Markdown, dashboard HTML, policies, templates, and optional compliance registers. Share under NDA with SOC 2 / HIPAA auditors.

## SaaS app inventory (Okta)

```bash
# identity.okta.enabled + OKTA_API_TOKEN
hipaa-audit apps discover
hipaa-audit apps list
hipaa-audit apps link okta-0oa1slack VND-001 --phi-risk low
```

Enable `saas_inventory.enabled: true` to enforce linkage on scan (`saas-inventory-tracked` check).
