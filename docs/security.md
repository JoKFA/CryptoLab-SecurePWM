# Security and Threat Model

## Threat Model

- Attacker steals the vault DB and backups.
- Attacker tampers with or reorders records.
- Compromised sync server (optional feature) observes ciphertext only.
- Partial: malware attempting memory scraping during unlock.
- Out of scope: compromised OS/kernel, keyloggers during password entry.

## Controls

- Zero-knowledge, client-side crypto only (docs/crypto-spec.md)
- AEAD with strict AD binding to context
- Per-entry keys; envelope encryption
- HMAC-chained audit log with verification
- scrypt KDF with calibrated parameters
- Optional TOTP
- Recovery via SLIP-0039 bound to vault
- SQLite WAL + `synchronous=FULL` for crash safety

## Logging and Telemetry

- No secrets in logs; redact sensitive values
- Structured logs with severity; default local only
- No analytics/telemetry

## Dependency and Supply Chain

- Pin critical dependencies; run `pip-audit`
- Run Bandit static checks
- SBOM generation (later) for releases

## FIPS Profile

- AES-256-GCM only; no XChaCha
- OpenSSL provider path; verify runtime selection

## Vulnerability Handling

- Triage within 48h; prepare patch; bump versions; document in CHANGELOG

