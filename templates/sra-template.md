# HIPAA Security Risk Assessment Template

**Version:** 1.1 · **License:** [MIT](../LICENSE)

> A first-cut Security Risk Assessment skeleton for teams bringing ePHI online.
> **Use as a starting point, not a finished assessment.** Requires engineering input,
> business context, and Privacy/Security Officer sign-off.

---

## How to use

1. Copy to `docs/security/sra.md` (or keep in `templates/` and link from your docs index).
2. Complete every section. Use **TBD** where unknown — never skip silently.
3. Add appendices as needed: [`state-law-overlay.md`](state-law-overlay.md), [`ai-risk-register.md`](ai-risk-register.md).
4. Engineering lead, Security Officer, and one operational owner sign section 8.
5. Re-review every **12 months** or after material system, vendor, or data-flow changes.

---

## 1. Scope & system description

| Field | Value |
|-------|-------|
| Application name | |
| Owner (organization + named individual) | |
| Date of this assessment | |
| Date of last assessment | |
| Reason | annual review / new system / material change / post-incident |

**Plain-language description of what the system does:**

**User categories** (staff, patients, vendors, clinicians, etc.):

**Environments in scope** (prod / staging / dev / regions):

**Explicitly out of scope:**

---

## 2. Data inventory

### 2.1 PHI elements

| Element | Source | Minimum-necessary justification | Retention |
|---------|--------|----------------------------------|-----------|
| | | | |

### 2.2 Sensitive non-PHI

| Element | Purpose | Retention |
|---------|---------|-----------|
| | | |

### 2.3 Data explicitly NOT collected

- *(e.g. SSN — never collected)*

---

## 3. Data flow & locations

Attach or link an architecture diagram: PHI at rest, in transit, accessors, retention.

### 3.1 Storage at rest

| Data | Location (region + service) | Encryption | BAA executed? |
|------|-------------------------------|------------|---------------|
| | | | |

### 3.2 Data in transit

| From | To | Protocol | TLS minimum |
|------|-----|----------|-------------|
| | | | |

### 3.3 Third parties touching PHI

| Vendor | Data scope | BAA date | Risk tier |
|--------|------------|----------|-----------|
| | | | |

---

## 4. Access controls

- **Identity provider:**
- **MFA:** required / role-based / optional
- **Session timeout:**
- **Joiner / mover / leaver SLA:**

| Role | Read | Write | Export |
|------|------|-------|--------|
| | | | |

**Break-glass:** who, when, logging, review cadence

---

## 5. Audit logging

| Question | Answer |
|----------|--------|
| What is logged? | |
| Where stored? | |
| Retention | |
| Tamper-evidence | |
| Review cadence | |

---

## 6. Threats & vulnerabilities

Rate **Likelihood** and **Impact** (Low / Med / High). Document residual risk after controls.

| # | Threat | Asset | L | I | Risk | Control | Residual |
|---|--------|-------|---|---|------|---------|----------|
| 1 | Stolen credentials | Admin PHI access | Med | High | High | MFA, audit alerts | Med |
| 2 | Misconfigured storage | Backups | Low | High | Med | IaC, public-access block | Low |
| 3 | Phishing / session hijack | Staff accounts | Med | High | High | MFA, short sessions | Med |
| 4 | Insider exfiltration | Bulk export | Low | High | Med | Export logging, RBAC | Med |
| 5 | Vendor compromise | Vendor-held PHI | Low | High | Med | BAA, vendor review | Med |
| 6 | Lost device | Web-app PHI | Med | Med | Med | Timeout, remote logout | Low |
| 7 | Ransomware | Production systems | Low | High | Med | Backups, IR plan | Med |

Add system-specific rows. If using clinical AI, copy rows from [`ai-risk-register.md`](ai-risk-register.md).

---

## 7. Incident response

| Field | Value |
|-------|-------|
| Incident commander | |
| Backup commander | |
| Comms channel | |
| External counsel | |
| Cyber insurance | |

**Detection:** map section 6 High/High threats to alerts (see `hipaa-audit scan` + SIEM).

**Breach clock:** 60-day HHS/individual notification process documented in `policies/breach-notification-plan.md`.

**Tabletop:** last run ___ · next scheduled ___ (≤ 12 months)

---

## 8. Sign-off

| Role | Name | Signature | Date |
|------|------|-----------|------|
| Privacy / Security Officer | | | |
| Engineering Lead | | | |
| Operational Owner | | | |

---

## Appendix A — Companion artifacts

| Artifact | Path |
|----------|------|
| Risk register | `templates/risk-register.md` |
| BAA register | `templates/baa-register.md` |
| Vendor risk register | `templates/vendor-risk-register.md` |
| State privacy overlays | `templates/state-law-overlay.md` |
| AI / ML risk rows | `templates/ai-risk-register.md` |
| Automated evidence | `evidence/latest/audit-report.json` from `hipaa-audit scan` |

## Appendix B — Intentionally abbreviated here

- Per-bucket cloud IAM dumps (use Prowler/Terraform evidence)
- Personnel training attestations (use `templates/workforce-training-log.md`)
- Penetration test reports (store in secure compliance drive, not git)
