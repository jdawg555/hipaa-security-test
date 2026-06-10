# Trust Center custom domain (P-18)

The trust center is a static site under `compliance/trust-center/`. Host it on your own domain for a Vanta/Drata-style public compliance page.

## Option A — Reverse proxy (recommended)

1. Set your public URL in `hipaa-audit.yaml`:

```yaml
trust_center:
  output_dir: compliance/trust-center
  public_url: https://trust.your-org.com
  contact_email: security@your-org.com
```

2. Run `hipaa-audit serve` or publish after each scan (automatic on scan).

3. Point nginx/Caddy/Cloudflare at the static folder or proxy to the workspace:

```nginx
server {
  server_name trust.your-org.com;
  root /path/to/repo/compliance/trust-center;
  index index.html;
}
```

## Option B — Cloudflare Pages / S3

1. After scan: upload `compliance/trust-center/` to your static host.
2. Set `trust_center.public_url` so links in the auditor bundle and workspace reference the live URL.

## Option C — Subpath on marketing site

Copy `index.html` into your corporate site's `/security` or `/trust` path during CI:

```bash
hipaa-audit scan . && cp compliance/trust-center/index.html ../marketing-site/public/trust/index.html
```

## DNS checklist

- CNAME `trust.your-org.com` → your CDN or load balancer
- TLS certificate (Let's Encrypt or Cloudflare)
- No authentication required for public trust page; keep auditor evidence behind `/audits` export + NDA
