# Multi-user RBAC via reverse proxy (P-28)

hipaa-audit workspace is designed as a **single-tenant, self-hosted** compliance console. It does not ship an internal user database, roles table, or per-route permission matrix — that keeps the MIT-licensed core small and avoids storing credentials in your compliance repo.

For teams that need **multi-user access with SSO and RBAC**, put the workspace behind your existing identity layer:

## Recommended pattern

```
User → IdP (Okta/Azure AD/Google) → OAuth2 proxy / IAP / Cloudflare Access → hipaa-audit serve
```

1. Run `hipaa-audit serve` bound to `127.0.0.1` only (default).
2. Terminate TLS and authentication at the proxy.
3. Map IdP groups to proxy roles (viewer vs admin).
4. Restrict write routes (`POST /settings`, `/integrations/*`, `/scan`, vendor/BAA mutations) to admin groups via proxy path rules.

## Example: oauth2-proxy

```bash
oauth2-proxy \
  --upstream=http://127.0.0.1:8787 \
  --http-address=0.0.0.0:4180 \
  --provider=oidc \
  --oidc-issuer-url=https://your-org.okta.com/oauth2/default \
  --client-id=... \
  --client-secret=... \
  --email-domain=your-org.com \
  --cookie-secure=true
```

Use `--allowed-group` (or provider-specific group claims) so only `compliance-admins` can reach mutating paths.

## Auditor and vendor portals

- **Auditor portal** — optional passphrase gate (`AUDITOR_PORTAL_PASSPHRASE`) is separate from workspace SSO; auditors do not need workspace accounts.
- **Vendor questionnaire portal** — tokenized URLs; no workspace login required.
- **Employee ack portal** — per-employee tokens in `compliance/acknowledgments.yaml`; distribute links via HR email, not shared workspace login.

## Why not built-in RBAC?

Vanta/Drata run multi-tenant SaaS with centralized auth. A self-hosted fork should integrate with **your** IdP and audit logs, not duplicate them. Documenting the proxy pattern (P-28) is the intended enterprise path.
