# HIPAA Security Risk Assessment — Sample Template
**Luxon AI · v0.1 · April 2026**

> **What this is:** a first-cut SRA template adapted from the actual one we use for Luxon Sync.
> Stripped of Luxon-specific content, kept short on purpose.
> **Use it as a starting skeleton, not a finished assessment.** Real SRAs need engineering input,
> business context, and a privacy/security officer's sign-off.
>
> Maintained by Luxon Medical · Send corrections / improvements to luxonmed@gmail.com
> · Future versions will live at github.com/LuxonMed.

---

## How to use this document

1. Copy this file into your repo (recommend `docs/security/sra.md`).
2. Walk through every section in order. Skipping is allowed; lying is not — write "TBD" where
   you don't have an answer yet.
3. Have your engineering lead, your security officer, and one operational owner review before you
   sign and date the bottom of section 8.
4. Re-review every 12 months at minimum, or after any material change to the system, vendors, or
   data flows.

---

## 1. Scope & system description

**Application name:**
**Owner (org + named individual):**
**Date of this assessment:**
**Date of last assessment:**
**Reason for this assessment** *(annual review / new system / material change / incident response)*:

**One-paragraph plain-English description of what the system does:**

**Categories of users** *(staff, patients, vendors, third-party clinicians, etc.)*:

**Locations covered** *(specific facilities, geographies, environments — prod / staging / dev)*:

**Out of scope for this assessment** *(name explicitly so reviewers know what wasn't covered)*:

---

## 2. Data inventory

### 2.1 PHI elements collected

| Element | Source | Justification (minimum necessary) | Retention period |
|---|---|---|---|
| *e.g. Patient name* | *EHR import* | *Required to label cases* | *7 years* |
| | | | |

### 2.2 Non-PHI but sensitive data

| Element | Why we collect it | Retention |
|---|---|---|
| *e.g. Staff email* | *Auth / audit log attribution* | *Active employment + 6 yrs* |
| | | |

### 2.3 Data we explicitly do NOT collect
*(naming what you avoid is part of the minimum-necessary story)*

- *e.g. Patient SSN — never collected, never derived*
- *e.g. Diagnosis codes — out of scope for v1*

---

## 3. Data flow & locations

**Diagram:** *(attach or link a one-page architecture diagram showing where PHI lives at rest,
where it crosses a wire, who can see it, and how long it stays)*

### 3.1 Storage at rest

| Data type | Location (region + service) | Encryption | BAA executed? |
|---|---|---|---|
| | | | |

### 3.2 Data in transit

| From | To | Protocol | TLS version |
|---|---|---|---|
| | | | |

### 3.3 Third parties that touch PHI

| Vendor | What they see | BAA on file (date) | Vendor risk tier |
|---|---|---|---|
| | | | |

---

## 4. Access controls

### 4.1 Identity provider
**Provider:**
**MFA enforcement** *(required / optional / by role)*:
**Session timeout:**
**Password policy** *(or passkey-only)*:

### 4.2 Roles & permissions

| Role | What they can read | What they can write | What they can export |
|---|---|---|---|
| | | | |

### 4.3 Joiner / mover / leaver process

- **Joiner:** *who provisions, on what trigger, within what SLA*
- **Mover:** *role-change checklist, who reviews, how often*
- **Leaver:** *deprovisioning steps, target SLA from termination, evidence of completion*

### 4.4 Privileged / break-glass access

- *Who has it, when it's used, how it's logged, who reviews the log*

---

## 5. Audit logging

**What is logged:** *(every read of PHI / every write / every export / every auth event)*
**Where logs live:** *(service + retention period)*
**Who can read logs:** *(should be a small, named set)*
**Tamper-evidence:** *(append-only? cryptographic chain? cloud-native protection?)*
**Log review cadence:** *(daily / weekly / quarterly + who does it)*

---

## 6. Threats & vulnerabilities

For each row: rate likelihood (Low / Med / High) and impact (Low / Med / High). The product
gives you the risk rating. Don't hide the High/High rows.

| # | Threat | Asset at risk | Likelihood | Impact | Risk | Existing control | Residual risk |
|---|---|---|---|---|---|---|---|
| 1 | *Stolen laptop with cached PHI* | *Patient names, MRNs* | *Med* | *High* | *High* | *Disk encryption + no local cache policy* | *Low* |
| 2 | *Compromised vendor BAA-side credential* | *All PHI in their system* | *Low* | *High* | *Med* | *Vendor SOC 2 + our MFA + quarterly key rotation* | *Med* |
| 3 | *Misconfigured cloud bucket exposes backups* | *Encrypted DB backups* | *Low* | *High* | *Med* | *IaC + bucket policy enforcement + alerting* | *Low* |
| 4 | *Insider exfiltration* | *Bulk PHI export* | *Low* | *High* | *Med* | *Export logging + rate limits + role gates* | *Med* |
| 5 | *Phishing → admin account takeover* | *All admin-accessible PHI* | *Med* | *High* | *High* | *MFA + admin-action audit + admin-only domain login* | *Med* |
| 6 | *Lost device of frontline user* | *PHI accessible via web app* | *Med* | *Med* | *Med* | *Short session timeout + remote logout* | *Low* |
| 7 | *Vendor goes out of business / loses BAA standing* | *All PHI in their system* | *Low* | *High* | *Med* | *Vendor exit plan + data portability test annually* | *Med* |

*Add rows specific to your system.*

---

## 7. Incident response

**Named incident commander** *(person, not role — who picks up the phone at 2am)*:
**Backup commander:**
**Communication channel during incident:**
**External counsel for breach analysis:**
**Cyber insurance carrier + policy #:**

### 7.1 Detection
*How would we know about the threats in section 6? For each high/high row, name the alert.*

### 7.2 60-day breach notification clock
*Who decides if a breach occurred. Who notifies HHS, affected individuals, media if applicable.
What template letters exist. Who keeps the register of past incidents.*

### 7.3 Tabletop exercise
**Last run:** *date*
**Next scheduled:** *date (no later than 12 mo from last)*

---

## 8. Sign-off

This SRA was reviewed and accepted on the date below by the named individuals.
Signing means: I have read it, I believe the controls described are in place, and I have
named myself accountable for re-review on the date in section 1.

| Role | Name | Signature | Date |
|---|---|---|---|
| Privacy / Security Officer | | | |
| Engineering Lead | | | |
| Operational Owner | | | |

---

## Appendix A — What this template intentionally leaves out

- **Vendor-specific risk language.** Real SRAs name your actual vendors and tier them.
  Use a separate vendor risk register.
- **State-law overlays.** California (CCPA), Texas (HB 300), New York (SHIELD Act),
  Washington (My Health My Data) all add requirements on top of HIPAA. Cover those in
  a state-overlay appendix specific to where your patients live.
- **Bucket-by-bucket cloud config.** This is intentionally short. Production SRAs include
  IAM dumps, network diagrams, and infrastructure-as-code references.
- **AI-specific risk rows.** If you're deploying clinical AI, add a separate section covering
  model drift, training-data provenance, prompt injection (for LLMs), and clinician override.
  We cover those in the paid Implementation Audit.

---

**Want help filling this in for a real system?** We do it in 2 weeks for $7,500
(or $3,750 for founding cohort clients).
[luxonmedical.com/ai](https://luxonmedical.com/ai)
