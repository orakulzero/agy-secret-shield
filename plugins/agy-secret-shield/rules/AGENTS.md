# AGY Secret Shield Operational Rules

1. Maintain 100% English-only source, documentation, and commit messages.
2. Enforce dynamic relative paths and never commit personal credentials or local user paths.
3. Quarantine detected session cookies (__Secure-1PSID, SAPISID) and secrets under Windows DPAPI envelopes.
4. Route lifecycle hooks through the single-process agy-golden-stack dispatcher.
