# Access Control Policy

**Status:** Draft v1.0  
**Owner:** Security Officer  
**Review cadence:** Annual  
**Last reviewed:** [DATE]

## 1. Purpose

Limit ePHI access to authorized workforce per minimum necessary (§164.308(a)(4), §164.312(a)(1)).

## 2. Requirements

- **Unique IDs:** No shared accounts for production PHI systems.
- **Authentication:** MFA required for all admin and clinical staff access.
- **Authorization:** Role-based access matrix maintained in SRA section 4.
- **Joiner/mover/leaver:** Provision via IdP within 1 business day; revoke within 4 hours of termination.
- **Break-glass:** Documented emergency access with post-use review within 24 hours.
- **Session:** Auto-logout after 15 minutes idle on PHI applications.
- **Review:** Quarterly access recertification by system owners.

## 3. Prohibited

- Sharing credentials
- Personal devices without MDM for PHI access (unless explicitly approved)
- Direct database access without ticket + approval
