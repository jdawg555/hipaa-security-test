# Encryption Policy

**Status:** Draft v1.0  
**Owner:** Security Officer  
**Review cadence:** Annual  
**Last reviewed:** [DATE]

## 1. At rest

All ePHI storage must use AES-256 or equivalent (AWS KMS, GCP CMEK, etc.). No PHI on unencrypted volumes or buckets.

## 2. In transit

TLS 1.2+ required for all PHI network paths. No PHI over unencrypted email or SMS body (use portal links / thin SMS).

## 3. Key management

- Customer-managed keys where supported
- Annual KMS key rotation
- Key access limited to break-glass + automated services
- No keys in source control

## 4. Endpoints

Full-disk encryption on laptops accessing PHI. Mobile devices require MDM + remote wipe.
