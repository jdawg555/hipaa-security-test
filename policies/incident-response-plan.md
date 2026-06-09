# Incident Response Plan

**Status:** Draft v1.0  
**Owner:** Security Officer  
**Review cadence:** Annual + post-incident  
**Last reviewed:** [DATE]

## 1. Severity levels

| Level | Definition | Response time |
|-------|------------|---------------|
| Sev 1 | Confirmed PHI breach or active exfiltration | Immediate |
| Sev 2 | Suspected PHI exposure, service down | < 1 hour |
| Sev 3 | Security event, no PHI confirmed | < 4 hours |
| Sev 4 | Near-miss, policy violation | < 1 business day |

## 2. Incident Commander

Primary: [Security Officer]  
Backup: [Engineering Lead]

## 3. Response phases

1. **Detect** — alerts, user report, audit scan failure
2. **Contain** — isolate affected systems, revoke credentials, enable kill switches
3. **Assess** — determine PHI elements involved, patient count, root cause
4. **Notify** — Privacy Officer → counsel → HHS/individuals per §164.404 (60-day clock)
5. **Recover** — restore from backup, patch, redeploy
6. **Learn** — post-mortem within 5 business days; update risk register

## 4. Breach notification

Privacy Officer coordinates with counsel. Document in breach log. HHS OCR portal if ≥ 500 individuals in a state.

## 5. Tabletop

Annual tabletop exercise required. Record scenario, participants, gaps, and remediation tickets.
