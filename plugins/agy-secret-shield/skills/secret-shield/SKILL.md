---
name: secret-shield
description: Autonomous secret, session cookie, Shannon entropy, and PII audit pipeline with Windows DPAPI quarantine and cryptographic cleanliness certification.
---

# AGY Secret Shield Skill

Provides automated 5-stage scanning and quarantine for credentials, session cookies, high-entropy tokens, and PII across codebases and conversational transcripts:

1. **Stage 1 (Signature & PII Scan)**: Matches Google cookies (`__Secure-1PSID`, `SAPISID`), GitHub PATs (`ghp_`, `gho_`), cloud API keys (`AIza`, `sk-`), PEM private keys, and user profile paths.
2. **Stage 2 (Shannon Entropy Analysis)**: Calculates token entropy to flag anomalous secret tokens (> 4.0 bits/char).
3. **Stage 3 (Git History & Index Audit)**: Audits tracked files and commits to ensure zero sensitive artifacts leak into version control.
4. **Stage 4 (Windows DPAPI Quarantine)**: Encrypts detected secrets into non-reversible redacted tags (`[REDACTED_DPAPI:<hash12>]`) using machine-locked Windows DPAPI.
5. **Stage 5 (Cryptographic Clean Certificate)**: Issues a deterministic SHA-256 cleanliness certificate verifying zero leaks.

## CLI Usage

```bash
# Run 5-stage audit on clean baseline
python -m agy_secret_shield.cli audit --profile clean_repo --json

# Run audit on a local directory
python -m agy_secret_shield.cli audit --repo-path ./my-project --json

# Seal a sensitive string under DPAPI
python -m agy_secret_shield.cli seal --secret "my-secret-key" --json
```
