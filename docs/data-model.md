# Data Model and Schema (SQLite)

This document defines the SQLite schema, indexes, PRAGMAs, and migration rules.

## PRAGMAs

Execute at open time:

```
PRAGMA journal_mode=WAL;
PRAGMA synchronous=FULL;
PRAGMA foreign_keys=ON;
PRAGMA secure_delete=ON;
```

## Tables

### vault_state

Holds global parameters and crypto profiles.

```
CREATE TABLE IF NOT EXISTS vault_state (
  id TEXT PRIMARY KEY,              -- uuid
  schema_version INTEGER NOT NULL,
  kdf TEXT NOT NULL,                -- "scrypt"
  kdf_params TEXT NOT NULL,         -- JSON
  kdf_salt BLOB NOT NULL,           -- 16-32 bytes
  aead_algo TEXT NOT NULL,          -- "xchacha20poly1305" or "aes256gcm"
  created_at INTEGER NOT NULL,
  last_unlock_at INTEGER
);
```

### entries

Stores only ciphertext fields and minimal metadata for AD reconstruction.

```
CREATE TABLE IF NOT EXISTS entries (
  id TEXT PRIMARY KEY,              -- uuid
  version INTEGER NOT NULL,
  nonce_content BLOB NOT NULL,
  ciphertext_content BLOB NOT NULL, -- ct||tag
  nonce_ke_wrap BLOB NOT NULL,
  wrapped_ke BLOB NOT NULL,         -- ct||tag
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  deleted INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_entries_updated_at ON entries(updated_at);
CREATE INDEX IF NOT EXISTS idx_entries_deleted ON entries(deleted);
```

Optional keyed-hash label index (opt-in; avoids plaintext labels):

```
CREATE TABLE IF NOT EXISTS entry_labels (
  entry_id TEXT PRIMARY KEY,
  label_hash BLOB NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_entry_labels_hash ON entry_labels(label_hash);
```

### audit_log

Tamper-evident log using chained HMAC (see crypto spec).

```
CREATE TABLE IF NOT EXISTS audit_log (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  action TEXT NOT NULL,
  payload BLOB,
  prev_mac BLOB,
  mac BLOB NOT NULL,
  actor TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
```

### config_secure

Encrypted key-value store for sensitive settings.

```
CREATE TABLE IF NOT EXISTS config_secure (
  k TEXT PRIMARY KEY,
  nonce BLOB NOT NULL,
  v BLOB NOT NULL
);
```

### totp (optional)

```
CREATE TABLE IF NOT EXISTS totp (
  id TEXT PRIMARY KEY,
  nonce BLOB NOT NULL,
  ciphertext_secret BLOB NOT NULL,
  created_at INTEGER NOT NULL
);
```

### sync_feed (optional)

```
CREATE TABLE IF NOT EXISTS sync_feed (
  seq INTEGER PRIMARY KEY,
  ts INTEGER NOT NULL,
  nonce BLOB NOT NULL,
  ciphertext_changeset BLOB NOT NULL,
  prev_hash BLOB NOT NULL
);
```

## Migrations

- Store `schema_version` in `vault_state`.
- Each migration script must:
  - Begin a transaction; set WAL checkpoint if needed.
  - Verify audit chain pre-migration.
  - Apply DDL/transformations.
  - Update `schema_version`.
  - Verify audit chain post-migration.
  - Commit.

## Integrity Checks

- Enforce length checks for nonces and tags.
- Validate that `aead_algo` is consistent across all records during reads.
- Optionally maintain a `meta` table for checksums of tables if needed.

