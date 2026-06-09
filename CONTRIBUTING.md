# Contributing

Thank you for helping make **hipaa-audit** a better free alternative to paid GRC platforms.

## MIT license

By contributing, you agree your contributions are licensed under the [MIT License](LICENSE).
Keep the copyright header intact in files you add.

## What we want

- **General-purpose checks** — no hardcoded org names, vendor pitches, or customer data
- **HIPAA Security Rule citations** — map controls to 45 CFR §164.308/310/312
- **Evidence artifacts** — checks should write JSON evidence auditors can inspect
- **Optional integrations** — scanners disabled by default; no required SaaS
- **Tests** — `pytest` for new check handlers and YAML catalog entries

## What we do not want

- Company-specific runbooks, BAAs, or architecture diagrams
- Real PHI, credentials, or patient identifiers in fixtures
- AGPL dependencies in the runtime package (tooling-only OK with NOTICE entry)
- Legal advice framed as guaranteed compliance

## Development setup

```bash
git clone https://github.com/jdawg555/hipaa-security-test.git
cd hipaa-security-test
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,aws]"
pytest -q
hipaa-audit scan .
```

## Adding a control

1. Edit `controls/hipaa-security-rule.yaml` — one control, clear citation
2. Implement handler in `hipaa_audit/checks/` (or extend existing module)
3. Add test in `tests/`
4. Update `docs/getting-started.md` if config changes

## Adding a policy template

1. Place in `policies/` with neutral `[Organization Name]` placeholders
2. Include review cadence and owner role fields
3. Register in `hipaa_audit/checks/policies.py` `REQUIRED_POLICIES` if HIPAA-core

## Pull request checklist

- [ ] No org-specific branding or contact info
- [ ] `pytest` passes
- [ ] `hipaa-audit scan .` runs without errors
- [ ] CHANGELOG.md updated under `[Unreleased]` or new version
- [ ] MIT-compatible dependencies only

## Security issues

See [SECURITY.md](SECURITY.md). Do not open public issues for exploitable vulnerabilities.
