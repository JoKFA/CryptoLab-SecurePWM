# SecurePWM Cryptography Specification v1

Status: Draft for implementation
Audience: SDEs implementing crypto, vault, audit, and recovery
Scope: Local vault encryption, audit chaining, recovery, optional sync

---

## 1. Goals and Non‑Goals

- Goals
  - Zero‑knowledge storage: no plaintext secrets leave the device.
  - Strong, misuse‑resistant envelope encryption with authenticated metadata.
  - Tamper‑evident audit log.
  - Robust recovery via k‑of‑n printed shares bound to the vault.
  - Versioned, upgradable crypto parameters.
- Non‑Goals
  - Hardening against a fully compromised OS or keyloggers.
  - Perfect in‑process zeroization in CPython (best‑effort only).
  - Complex searchable encryption. Only optional keyed-hash labels are considered.

## 2. Threat Model and Assumptions

- In scope
  - Theft of the vault database and local backups.
  - Tampering, rollback, or reordering of records.
  - Compromised sync server (optional feature) observing only ciphertext.
- Partial
  - Malware scraping memory during unlock (we minimize plaintext lifetimes; cannot eliminate).
- Out of scope
  - Compromised OS, kernel, or hardware.

## 3. Primitives and Libraries

- KDF (master → vault key): scrypt with versioned params.
  - Default desktop profile: N=2^19, r=8, p=1; calibrated to ~150–400 ms and 64–256 MB.
  - Option: Argon2id may be added via ADR and migration.
- AEAD (default): XChaCha20‑Poly1305 (libsodium/PyNaCl), 24B nonce, 16B tag.
- AEAD (FIPS profile): AES‑256‑GCM (cryptography), 12B nonce, 16B tag.
- KDF for subkeys: HKDF‑SHA‑256 (cryptography), info labels per‑context.
- MAC for audit chain: HMAC‑SHA‑256.
- RNG: OS CSPRNG via libsodium/`secrets`.
- Recovery: SLIP‑0039 Shamir mnemonic (k‑of‑n) with built‑in checksum, plus vault binding (Section 10).
- Optional PQ for sync: ML‑KEM (Kyber‑768) via python‑oqs in a hybrid encapsulation (Section 11).

Identifiers:

- AEAD algorithms
  - `xchacha20poly1305` (id: 1) [default]
  - `aes256gcm` (id: 2) [FIPS]
- KDF algorithms
  - `scrypt` (id: 1)

## 4. Key Hierarchy

- Master password (user secret)
  - scrypt(salt_master, params) → `VaultKey` (KV, 32 bytes)
- Subkeys (HKDF info labels, salt empty string)
  - `K_content = HKDF(KV, info="spwm/content/v1", len=32)`
  - `K_audit   = HKDF(KV, info="spwm/audit/v1",   len=32)`
  - `K_config  = HKDF(KV, info="spwm/config/v1",  len=32)`
- Per‑entry content keys: random 32‑byte `EntryKey` (KE) per item.
  - KE is wrapped using AEAD with `K_content` (not KV directly) to reduce blast radius and enable profile switches.

Rationale: envelope encryption isolates entries; HKDF provides domain separation and rotation paths.

## 5. Associated Data (AD) Discipline

All AEAD operations MUST include canonical associated data (AD) binding the ciphertext to its context.

- Canonicalization: JSON Canonicalization Scheme (JCS, RFC 8785‑style). Implementation guidance:
  - Use JSON objects containing only strings and integers.
  - UTF‑8 encode the canonical JSON: `json.dumps(obj, separators=(",", ":"), sort_keys=True, ensure_ascii=False)`.
  - No floats, no binary; encode binary as lowercase hex if needed.

AD schema fields (by context):

- Entry key wrap AD `ctx="ke_wrap"`
  - `ctx`: "ke_wrap"
  - `vault_id`: UUID string (lowercase, hyphenated)
  - `entry_id`: UUID string
  - `aead`: algorithm string (e.g., "xchacha20poly1305")
  - `schema_version`: integer
  - `entry_version`: integer

- Entry content AD `ctx="entry_content"`
  - `ctx`: "entry_content"
  - `vault_id`, `entry_id`, `aead`, `schema_version`, `entry_version`
  - `created_at`: Unix seconds (int)
  - `updated_at`: Unix seconds (int)

- Config KV AD `ctx="config_kv"`
  - `ctx`: "config_kv"
  - `vault_id`, `key`: config key string

Any AD changes invalidate decrypt; AD must be reconstructible from stored metadata.

## 6. Nonce Management

- XChaCha20‑Poly1305: 24‑byte nonces generated randomly per encryption.
- AES‑GCM (FIPS profile): 12‑byte random nonces; enforce uniqueness checks per key in tests.
- Nonces are stored alongside ciphertext; never reused with same key.

## 7. Data Model and Storage (Crypto‑Relevant)

Tables (only crypto‑relevant columns listed):

- `vault_state`
  - `id` TEXT (uuid)
  - `schema_version` INTEGER
  - `kdf` TEXT (e.g., "scrypt")
  - `kdf_params` TEXT (JSON)
  - `kdf_salt` BLOB (16–32 bytes)
  - `aead_algo` TEXT (e.g., "xchacha20poly1305")
  - `created_at` INTEGER
  - `last_unlock_at` INTEGER (nullable)

- `entries`
  - `id` TEXT (uuid)
  - `version` INTEGER
  - `nonce_content` BLOB
  - `ciphertext_content` BLOB  (ct||tag)
  - `nonce_ke_wrap` BLOB
  - `wrapped_ke` BLOB          (ct||tag)
  - `created_at` INTEGER
  - `updated_at` INTEGER
  - `deleted` INTEGER (0/1)

- `audit_log`
  - `seq` INTEGER PRIMARY KEY
  - `ts` INTEGER
  - `action` TEXT (short verb)
  - `payload` BLOB (optional ciphertext)
  - `prev_mac` BLOB (32)
  - `mac` BLOB (32)
  - `actor` TEXT (optional, minimal)

- `config_secure`
  - `k` TEXT, `nonce` BLOB, `v` BLOB (ct||tag)

## 8. Ciphertext Containers

We store nonce and ciphertext separately in DB columns; tags are appended to ciphertext (ct||tag).

Container invariants:

- For XChaCha20‑Poly1305: `len(nonce)=24`, `len(tag)=16`.
- For AES‑256‑GCM: `len(nonce)=12`, `len(tag)=16`.
- Algorithm used comes from `vault_state.aead_algo`; future migrations must rewrap.

## 9. KDF and Parameter Tuning

- scrypt parameters stored in `vault_state.kdf_params` JSON:
  - `{ "N": 524288, "r": 8, "p": 1, "dkLen": 32 }`
- Salt: `kdf_salt` 16–32 bytes random.
- Calibration: on first init or explicit retune, probe parameters to reach target latency window (150–400 ms) and memory (64–256 MB). Store result.
- Vault key rotation: derive new KV’ with new params and atomically rewrap all KE and config entries.

## 10. Audit Log MAC Chain

- MAC key: `K_audit` from HKDF(KV, info="spwm/audit/v1").
- Entry MAC input (canonical JSON, UTF‑8):
  - Object fields: `seq`, `ts`, `action`, `payload_hash`, `prev_mac` (hex lowercase), `actor` (optional).
  - `payload_hash` = SHA‑256 over `payload` bytes if present; otherwise empty string.
- MAC algorithm: HMAC‑SHA‑256 over the canonical JSON bytes.
- Verification walks from the earliest record, recomputing and comparing.
- Periodic anchors: every 256 events, store an exported anchor (hash of last MAC and seq) to enable external notarization (optional feature).

## 11. Recovery (k‑of‑n)

- Recovery secret: 32‑byte `K_recovery` derived from KV via HKDF info="spwm/recovery/v1".
- Export: split `K_recovery` into SLIP‑0039 mnemonic shares (user chooses k of n).
- Vault binding: along with mnemonics, print an AEAD‑authenticated metadata card:
  - AEAD key = HKDF(KV, info="spwm/recovery_meta/v1")
  - AD: `{ ctx: "recovery_meta", vault_id, schema_version, aead }`
  - Ciphertext payload includes `vault_id`, creation timestamp, and a checksum.
- Combine: user inputs k shares to reconstruct `K_recovery`. System verifies the metadata AEAD with AD, ensuring shares belong to this vault.
- Reset/unlock policies are defined in product docs; crypto ensures authenticity and binding.

## 12. Optional PQ for Sync (Hybrid)

- Sync change‑sets are encrypted locally with a random 32‑byte CEK using vault’s current AEAD.
- For sharing across devices, CEK is hybrid‑encrypted per recipient device public key:
  - Perform ML‑KEM encapsulation to produce (ct_kem, ss) and X25519 (or Ed25519‑X25519 conversion) ECDH; combine via KDF to a wrap key.
  - Use AEAD to wrap CEK with AD including `feed_seq`, `prev_hash`, and `vault_id`.
- PQ is optional and isolated to sync; not used for local vault storage.

## 13. FIPS Profile

- Enable via configuration profile or environment variable `SPWM_COMPLIANCE=FIPS`.
- Constraints: AES‑256‑GCM only; no XChaCha; allowed RNG and KDF via OpenSSL provider.
- Implementation must keep code paths isolated for verification.

## 14. API Contracts (Python 3.12+)

Module: `securepwm.crypto`

Types:

```python
from dataclasses import dataclass
from typing import Literal, Mapping

AeadAlgo = Literal["xchacha20poly1305", "aes256gcm"]

@dataclass(frozen=True)
class AeadParams:
    algo: AeadAlgo
    nonce_len: int  # 24 for XChaCha, 12 for AES-GCM
    tag_len: int    # 16

@dataclass(frozen=True)
class Encrypted:
    nonce: bytes
    ciphertext: bytes  # includes tag appended

def kdf_scrypt(master_password: str, salt: bytes, N: int, r: int, p: int, dk_len: int = 32) -> bytes: ...

def hkdf_derive(key: bytes, info: str, length: int = 32) -> bytes: ...

def canonical_ad(ad: Mapping[str, object]) -> bytes: ...  # JCS canonical JSON UTF-8

def aead_encrypt(key: bytes, plaintext: bytes, ad: Mapping[str, object], params: AeadParams) -> Encrypted: ...

def aead_decrypt(key: bytes, enc: Encrypted, ad: Mapping[str, object], params: AeadParams) -> bytes: ...

def random_bytes(n: int) -> bytes: ...

def zeroize(b: bytearray) -> None: ...  # best-effort sodium_memzero
```

Vault‑level helpers:

```python
def derive_vault_keys(master_password: str, kdf_salt: bytes, kdf_params: dict, aead_algo: AeadAlgo) -> dict:
    """Returns KV and subkeys { 'KV': bytes, 'K_content': bytes, 'K_audit': bytes, 'K_config': bytes } and AeadParams."""

def wrap_entry_key(K_content: bytes, entry_id: str, vault_id: str, entry_version: int, KE: bytes, params: AeadParams) -> Encrypted: ...

def unwrap_entry_key(K_content: bytes, entry_id: str, vault_id: str, entry_version: int, enc: Encrypted, params: AeadParams) -> bytes: ...

def encrypt_entry_content(KE: bytes, vault_id: str, entry_id: str, entry_version: int, created_at: int, updated_at: int, plaintext: bytes, params: AeadParams) -> Encrypted: ...

def decrypt_entry_content(KE: bytes, vault_id: str, entry_id: str, entry_version: int, created_at: int, updated_at: int, enc: Encrypted, params: AeadParams) -> bytes: ...

def audit_mac(K_audit: bytes, seq: int, ts: int, action: str, payload: bytes | None, prev_mac: bytes | None, actor: str | None = None) -> bytes: ...
```

All functions MUST:

- Validate inputs (nonce lengths, key sizes, AD required fields).
- Refuse to operate if algorithm mismatch with profile.
- Avoid logging secrets; raise typed exceptions without secret data.

## 15. Invariants and Error Handling

- AEAD decrypt MUST fail on any AD mismatch, nonce reuse, or tampering.
- Always verify full MAC/tag; use constant‑time comparisons.
- Reject empty or malformed AD objects.
- Secrets should be handled as `bytes`/`bytearray`; zeroize `bytearray` where feasible.

Exceptions (names suggestive):

- `CryptoError` (base), `KdfError`, `AeadError`, `AuditMacError`, `NonceError`.

## 16. Test Requirements

- Unit vectors
  - scrypt: compare derived keys to library vectors for chosen params.
  - AEAD: verify encrypt/decrypt with known vectors per algorithm.
- Property tests (Hypothesis)
  - Round‑trip for random plaintext/AD across sizes [0, 64KiB].
  - Tamper: flip 1 bit in ct/tag/nonce/AD → decryption fails.
  - Nonce uniqueness: track generated nonces per key in tests; detect duplicates.
- Misuse tests
  - Wrong AD fields or values → fail.
  - Swap KE between entries → fail.
  - Reuse nonce (same key) → test should detect; library may not, but we gate with test harness.
- Audit chain tests
  - Insertion, deletion, reorder cause verification failure.
  - Anchor export/import stable across platforms.

## 17. Migration and Versioning

- `schema_version` in DB governs storage and AD schema.
- `aead_algo` stored in `vault_state`; upgrades require rewrap of KE and content.
- Provide migration tooling that:
  - Verifies audit chain pre‑ and post‑migration.
  - Uses WAL and atomic batched transactions.

## 18. Example Flows (Normative)

Initialization:

1. Generate `kdf_salt` (16–32B) and choose scrypt params; derive `KV`.
2. Derive subkeys via HKDF; set `aead_algo` and initialize audit MAC key.
3. Write `vault_state` and append `VAULT_INIT` audit.

Add Entry:

1. Generate random `KE` (32B).
2. Wrap `KE` with `K_content` using AD `ke_wrap`.
3. Encrypt plaintext with `KE` using AD `entry_content`.
4. Store nonces and ciphertexts; append `ENTRY_ADD` audit with payload hash.

Read Entry:

1. Unwrap `KE` with `K_content` and AD `ke_wrap`.
2. Decrypt content with `KE` and AD `entry_content`.

Rotate Master:

1. Calibrate new scrypt params; derive `KV'` and subkeys.
2. Atomically rewrap all `KE` and content under new subkeys.
3. Append `ROTATE_MASTER` audit.

## 19. Implementation Notes

- Use libsodium bindings where possible; fall back to cryptography FIPS paths.
- Keep AD construction in one place; never hand‑roll per call.
- Avoid variable‑time comparisons for MACs and tags.
- Deny unsafe parameter sets; enforce minimums.
- Never persist plaintext or keys to disk or logs.

---

This document is the authoritative reference for crypto behavior in SecurePWM v1. Any divergence requires an ADR and a version bump.

