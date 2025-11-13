# Sync Specification (Optional)

Sync is append-only and encrypted end-to-end. It is optional and isolated from core vault storage.

## Model

- Local change-sets encrypted with a random 32-byte CEK under current AEAD algo
- Each feed record includes `seq`, `ts`, `prev_hash`, `nonce`, `ciphertext_changeset`
- Device sharing uses hybrid encryption (PQ optional); per-device keys

## Providers

- `LocalDirProvider` for filesystem
- Future: cloud providers (S3, GCS, WebDAV)

## API

See docs/api-contracts.md (SyncService, SyncProvider).

## Conflict Resolution

- Append-only prevents in-place conflict; merges happen by applying missing change-sets then reappending
- Detect forks via `prev_hash`; resolve using latest anchor + rebase strategy

