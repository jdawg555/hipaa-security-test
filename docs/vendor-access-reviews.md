# Vendor risk & access reviews

v1.6 adds Vanta/Drata-style **vendor questionnaires** and **access review campaigns** without a subscription.

## Vendor register (SIG-lite)

1. Enable in `hipaa-audit.yaml`:

```yaml
vendors:
  enabled: true
  register_path: compliance/vendors.yaml
```

2. Bootstrap:

```bash
hipaa-audit vendor init
hipaa-audit vendor add "Acme EHR" --phi-access full --risk-tier high --baa
hipaa-audit vendor review VND-001 --complete --reviewer security@your-org.com
```

3. Use `templates/vendor-questionnaire.md` when collecting vendor attestations.

Checks on scan: BAA for PHI vendors, review cadence, SIG-lite completeness → control `vendor-register-current` (§164.308(b)(1)).

## Access review campaigns

1. Enable:

```yaml
access_reviews:
  enabled: true
  register_path: compliance/access-reviews.yaml
  max_campaign_age_days: 120
```

2. Run a quarterly campaign:

```bash
hipaa-audit access-review start "Q2 2026 review" security@your-org.com \
  --systems github:GitHub,aws-iam:AWS IAM,okta:Okta
hipaa-audit access-review decide AR-2026-Q2-01 github user@example.com retain eng-lead@your-org.com
hipaa-audit access-review complete AR-2026-Q2-01
```

Checks on scan: overdue campaigns, incomplete system reviews, recent completion → `access-review-campaign` (§164.308(a)(4)).

## Probo export

Vendor and access-review status appears in `hipaa-audit export probo` alongside automated check evidence for import into [getprobo/probo](https://github.com/getprobo/probo).
