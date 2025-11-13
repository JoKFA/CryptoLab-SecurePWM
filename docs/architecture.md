# SecurePWM Architecture Overview

Status: Implementable v1 blueprint

## Objectives

- Zero-knowledge: all crypto local; vault stores only ciphertext.
- Robust crypto: AEAD envelope encryption; versioned parameters; strict AD discipline.
- Integrity and auditability: HMAC-chained audit log with verification.
- Recovery: k-of-n paper recovery bound to vault.
- Usability: complete CLI; desktop app later; crash-safe and portable.

## System Components

- CLI (`securepwm.cli`): Typer-based commands for all user flows.
- Vault Service (`securepwm.vault`): business logic for init/unlock/CRUD/rotate/backup.
- Crypto Service (`securepwm.crypto`): KDF, AEAD, HKDF, RNG; per docs/crypto-spec.md.
- Audit Service (`securepwm.audit`): append/verify/export HMAC chain.
- Policy Engine (`securepwm.policy`): strength, reuse, expiry, passgen.
- Recovery Service (`securepwm.recovery`): SLIP-0039 shares; combine/verify; binding.
- TOTP Service (`securepwm.totp`): optional second factor via pyotp.
- Sync Service (`securepwm.sync`): optional, encrypted append-only feed; provider adapters.
- UI (`securepwm.ui`): desktop app (PySide6) after CLI stabilizes.

## Layering and Dependencies

- `crypto` has no internal dependencies; used by all other services.
- `vault` depends on `crypto`, `audit`, `policy`.
- `audit` depends on `crypto` (HKDF/HMAC), no DB coupling beyond repo interface.
- `policy` is pure; optional zxcvbn dependency.
- `recovery` depends on `crypto` for binding; SLIP-0039 lib.
- `sync` depends on `crypto` for bundle encryption; provider interfaces.
- `cli` depends on all; `ui` reuses services, no custom crypto.

## Repository Structure

```
securepwm/
  cli/          # Typer commands wired to services
  vault/        # repo (sqlite) + service orchestration + migrations
  crypto/       # aead, kdf, hkdf, rng, params, errors
  audit/        # HMAC chain, verification, export/anchors
  policy/       # rules, passgen, zxcvbn integration
  recovery/     # SLIP-0039 integration and binding
  totp/         # TOTP setup/verify
  sync/         # append-only change feed + providers (optional)
  ui/           # desktop app (later)
  utils/        # serialization, time, platform, secure I/O
docs/
tests/
scripts/
```

## Cross-Cutting Concerns

- Crash safety: SQLite WAL, `synchronous=FULL`, atomic batched ops, integrity checks.
- Logging: structured, redacted; never log secrets or plaintext.
- Configuration: minimal, stored encrypted in `config_secure` when sensitive.
- Platform: Windows/macOS/Linux; package with PyInstaller later.

## Key Flows (Summary)

- Init: scrypt→KV; HKDF subkeys; write vault_state; audit VAULT_INIT.
- Add: random KE; wrap with K_content; AEAD content; audit ENTRY_ADD.
- Read: unwrap KE; decrypt content.
- Rotate master: derive KV'; rewrap; audit ROTATE_MASTER.
- Recovery: generate/print SLIP-0039 shares; combine to reconstruct.

## Roadmap (Milestones)

- M0: Project bootstrap, tooling, docs skeleton.
- M1: Crypto service (scrypt, AEAD, HKDF, RNG) + tests.
- M2: Vault schema + CRUD + init/add/get CLI.
- M3: Audit chain + verify/export; integrate flows.
- M4: Policy engine + passgen + reuse/expiry checks.
- M5: TOTP integration in CLI.
- M6: Recovery (SLIP-0039) flows.
- M7: Desktop app MVP; clipboard hygiene.
- M8: Optional sync MVP; local provider.
- M9: Master rotation tool; backup/restore.
- M10: Hardening; performance; docs; review readiness.

## Non-Goals (v1)

- Encrypted search beyond keyed-hash labels.
- Server-side crypto or auto-fill browser integrations.

