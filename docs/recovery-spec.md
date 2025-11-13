# Recovery Specification

We provide a paper-based k-of-n recovery using SLIP-0039 mnemonics, bound to the vault to prevent mix-ups.

## Secrets

- `K_recovery = HKDF(KV, info="spwm/recovery/v1", len=32)`
- Split `K_recovery` into SLIP-0039 shares (n total, k required)

## Vault Binding

- Print a metadata card authenticated under AEAD:
  - AEAD key: `HKDF(KV, info="spwm/recovery_meta/v1")`
  - AD: `{ ctx: "recovery_meta", vault_id, schema_version, aead }`
  - Payload: `vault_id`, created timestamp, checksum

## Flows

- Initialize: generate shares; print mnemonics + metadata card; audit RECOVERY_INIT
- Combine: user inputs k shares; reconstruct `K_recovery`; verify metadata authenticity; audit RECOVERY_COMBINE
- Reset: allowed operations are product-defined; crypto validates authenticity only

## Printing

- Print shares with vault id, sequence, checksum; avoid QR with embedded secrets
- Offer PDF export with big font and instructions; do not store PDF on disk unless user chooses path

