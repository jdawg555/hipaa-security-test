# Vanta / Drata parity roadmap

This is the **master gap matrix** and build order for hipaa-audit. Every feature we add should map to a row here.

**Status legend:** `shipped` · `partial` · `scaffold` · `planned` · `wont` (intentionally OSS-different)

Run live status: `hipaa-audit parity`

---

## Product pillars (how Vanta/Drata organize)

| Pillar | Vanta/Drata | Our workspace nav | Primary data |
|--------|-------------|-------------------|--------------|
| Compliance automation | Tests + evidence | Monitoring, Integrations | `evidence/latest/`, checks |
| Risk & vendors | VRM, questionnaires | Vendors | `compliance/vendors.yaml` |
| Personnel | Training, devices, acks | Personnel, Devices | acks CSV, devices YAML |
| Access governance | Access reviews | Access reviews | `compliance/access-reviews.yaml` |
| Customer trust | Trust Center | Audits & trust | `compliance/trust-center/` |
| Audit operations | Auditor portal, PBC | Audits & trust | auditor portal + ZIP |
| Frameworks | 35+ cross-mapped | Settings (HIPAA+SOC2+ISO) | `controls/*.yaml` |

---

## Gap matrix

| ID | Capability | Vanta/Drata | Us today | Target | Build pattern | Phase |
|----|------------|-------------|----------|--------|---------------|-------|
| P-01 | Web compliance workspace | SaaS app | **shipped** v2 `serve` | full | `workspace/server.py` | 1 |
| P-02 | Onboarding wizard | Guided setup | **shipped** | full | `/onboarding` + bootstrap | 1 |
| P-03 | Integration toggles | Connect UI | **partial** toggles + test button | OAuth connect flow | `platform/adapters/` + Integrations page | 2 |
| P-04 | Continuous monitoring | Hourly cloud tests | **partial** manual + scheduler |默认 24h + CI | `scan_runner` + `workspace.schedule_hours` | 2 |
| P-05 | Control library + CFR | Pre-built | **shipped** 77+ HIPAA | + HITRUST slice | `controls/hipaa-*.yaml` | 1 |
| P-06 | Multi-framework crosswalk | Test once, map many | **partial** SOC2+ISO supplements | shared check refs | `controls/soc2-*` `iso27001-*` | 2 |
| P-07 | Posture score + history | Dashboard KPI | **shipped** | trend charts in UI | `posture.py` + workspace charts | 3 |
| P-08 | Remediation tasks + owners | Assigned tasks | **shipped** v2.2 `/tasks` UI | Slack notify | `tasks.py` + workspace tasks page | 3 |
| P-09 | Policy library | In-app editor | **partial** git markdown | web editor + version | `policies/` + new editor module | 4 |
| P-10 | Personnel training | LMS integration | **partial** CSV | HRIS adapter (Bamboo, Rippling) | `personnel/` + HRIS registry | 4 |
| P-11 | Policy acknowledgments | In-app ack | **partial** YAML | employee portal link | extend personnel module | 4 |
| P-12 | MDM / endpoints | Agent (Jamf/Kandji) | **partial** CSV import | Jamf Pro API + Intune Graph | `devices.py` + API adapters | 4 |
| P-13 | Access reviews | In-app campaigns | **partial** UI builder (v2.2) | IdP user picker | `access_reviews.py` + workspace forms | 3 |
| P-14 | SaaS inventory | Auto-discover apps | **partial** Okta/Google | + Azure AD, GitHub apps | `apps.py` adapters | 3 |
| P-15 | Vendor register | VRM | **shipped** YAML | UI CRUD | vendors workspace forms | 3 |
| P-16 | Vendor questionnaires | Portal + email | **partial** static HTML | send email + track opens | `vendor_portal.py` + notify | 4 |
| P-17 | BAA tracking | Document store | **partial** markdown register | structured BAA objects | `compliance/baas.yaml` | 3 |
| P-18 | Trust Center | Hosted public | **shipped** static publish | custom domain helper | `trust_center.py` | 2 |
| P-19 | Auditor portal | Login + requests | **partial** static + passphrase | request/response threads | `auditor_portal.py` → SQLite tickets | 5 |
| P-20 | Auditor evidence ZIP | One-click PBC | **shipped** export auditor | scheduled auto-export | `export_auditor.py` | 2 |
| P-21 | Cloud AWS | Deep checks | **partial** ~20 checks | full Prowler crosswalk | `aws.py` + Prowler ingest | 2 |
| P-22 | Cloud GCP/Azure | Multi-cloud | **planned** | Prowler Azure/GCP | integrations adapter | 5 |
| P-23 | GitHub / GitLab | Repo security | **partial** GitHub | GitLab parity | `github.py` + `gitlab.py` | 4 |
| P-24 | IdP Okta/Google | MFA, users | **partial** API checks | connection wizard | `identity.py` | 2 |
| P-25 | Vuln scanning | Snyk, etc. | **partial** Trivy/OSV ingest | Snyk API optional | `integrations.py` | 3 |
| P-26 | IaC scanning | Built-in | **partial** Checkov ingest | PR check Action | checkov in CI template | 2 |
| P-27 | Slack notifications | Alerts | **shipped** `--notify` | workspace notification settings | `notify.py` | 2 |
| P-28 | Multi-user RBAC | Roles | **wont** single-tenant OSS | optional auth proxy doc | document SSO reverse proxy | 6 |
| P-29 | AI questionnaire fill | Agents | **planned** | optional local LLM assist | separate opt-in module | 6 |
| P-30 | 300+ SaaS integrations | Marketplace | **wont** full parity | curated registry + adapter SDK | `platform/` adapter interface | ongoing |

---

## Phased build order

### Phase 1 — Product shell (done v2.0)
Workspace, onboarding, nav, scan from UI, Docker.

### Phase 2 — Connection layer
- Integration connection wizard (test creds, status badge)
- Prowler-first cloud depth
- Auto-scan defaults + CI template polish

### Phase 3 — Workflow UI (close the YAML gap)
- Tasks page with owners/due dates in UI
- Access review campaign builder
- Vendor CRUD in UI
- BAA structured register

### Phase 4 — HR + endpoints + policies
- Jamf / Intune API adapters
- HRIS webhook or CSV sync for personnel
- Policy web editor with version history

### Phase 5 — Audit operations
- Auditor request queue (PBC list, upload, status)
- Evidence manifest auto-refresh

### Phase 6 — Enterprise optional
- RBAC via external auth
- AI assist (opt-in, local)

---

## How to pick up work

1. Choose a row in the matrix (e.g. `P-13`).
2. Read [EXTENSION_MODEL.md](../architecture/EXTENSION_MODEL.md).
3. Run `hipaa-audit scaffold module <name>` (or `integration <id>`).
4. Implement: registry entry → check module → workspace page → test → update `platform/capabilities.yaml` status.
5. `hipaa-audit parity` must show the row moved to `partial` or `shipped`.

---

## What we intentionally won't replicate

| Vanta/Drata | OSS stance |
|-------------|------------|
| Hosted multi-tenant SaaS | Self-hosted workspace + Docker |
| 300+ proprietary connectors | Adapter SDK + top 20 + ingest |
| MDM agent on laptop | API/CSV from Jamf/Intune |
| Legal/policy advice | Templates + counsel disclaimer |

Positioning: **self-hosted trust management for engineering-led healthcare teams** — not a dollar-for-dollar Vanta clone.
