# Extension model — how to build Vanta/Drata-style features

Every new capability follows the same **five layers**. Do not skip layers.

```
┌─────────────────────────────────────────────────────────┐
│ 1. SURFACE — workspace page and/or CLI command          │
├─────────────────────────────────────────────────────────┤
│ 2. REGISTER — YAML/CSV data the org owns (gitignored)   │
├─────────────────────────────────────────────────────────┤
│ 3. CHECK MODULE — automated test(s) in hipaa_audit/     │
├─────────────────────────────────────────────────────────┤
│ 4. CONTROL — maps check to HIPAA/SOC2/ISO control       │
├─────────────────────────────────────────────────────────┤
│ 5. INTEGRATION ADAPTER — optional external API/ingest   │
└─────────────────────────────────────────────────────────┘
```

---

## Layer 1: Surface (workspace)

| Add | File(s) |
|-----|---------|
| Nav item | `workspace/templates/base.html` |
| Page | `workspace/templates/<module>.html` |
| Route | `workspace/server.py` |
| Toggle (if integration) | `workspace/config_store.py` → `integration_status()` |

**Rule:** Users should complete the workflow without reading CLI docs.

---

## Layer 2: Register (org data)

| Pattern | Path | Example |
|---------|------|---------|
| Entity list | `compliance/<name>.yaml` | `vendors.yaml` |
| Example | `compliance/<name>.example.yaml` | committed |
| Gitignore | `compliance/<name>.yaml` | org-specific |

Loader/saver lives in `hipaa_audit/<module>.py`.

---

## Layer 3: Check module

```python
# hipaa_audit/checks/<module>.py
def run(check, *, repo_path, config, evidence_dir) -> CheckResult:
    if not config.get("<module>", {}).get("enabled"):
        return skip(...)
    ...
```

Register in `hipaa_audit/checks/base.py` → `RUNNERS`.

**Handlers** are named in `controls/*.yaml`:

```yaml
checks:
  - id: my-check
    module: my_module
    handler: my_handler
```

---

## Layer 4: Control mapping

Add to `controls/hipaa-security-rule.yaml` or framework supplement.

One control may reference multiple checks. Reuse handlers across HIPAA / SOC2 / ISO.

---

## Layer 5: Integration adapter

For external systems, implement `hipaa_audit/platform/adapters/<id>.py`:

```python
class MyAdapter(IntegrationAdapter):
    id = "jamf"
    def test_connection(self, config) -> ConnectionResult: ...
    def discover(self, config) -> list[dict]: ...  # optional
```

Register in `platform/integrations_registry.yaml`.

Auth types: `env_vars` | `oauth` (future) | `file_path` | `ingest_only`

---

## Scaffolding commands

```bash
# New check module + example register + registry stub
hipaa-audit scaffold module baa_tracking

# New external integration adapter
hipaa-audit scaffold integration jamf

# Show parity matrix
hipaa-audit parity
hipaa-audit parity --phase 3
```

Generated files are listed in `platform/scaffold_manifest.yaml`.

---

## Testing checklist

- [ ] Unit test in `tests/test_<module>.py`
- [ ] Check returns `skip` when disabled
- [ ] Workspace route returns 200 after onboarding
- [ ] `hipaa-audit scan .` includes new check when enabled
- [ ] Update `platform/capabilities.yaml` status

---

## PR template (mental)

1. **Parity ID:** P-XX from PARITY.md
2. **User story:** As compliance lead, I can … without CLI
3. **Layers touched:** surface / register / check / control / adapter
4. **Credentials:** env vars documented in integrations registry
