# API Contracts (Python 3.12+)

This document defines implementable interfaces and data types. Use these as the source of truth while building the codebase.

Crypto details are specified in docs/crypto-spec.md and referenced here.

## Package: securepwm.crypto

See docs/crypto-spec.md for full contracts. Summary:

```python
from dataclasses import dataclass
from typing import Literal, Mapping

AeadAlgo = Literal["xchacha20poly1305", "aes256gcm"]

@dataclass(frozen=True)
class AeadParams:
    algo: AeadAlgo
    nonce_len: int
    tag_len: int

@dataclass(frozen=True)
class Encrypted:
    nonce: bytes
    ciphertext: bytes  # ct||tag

def kdf_scrypt(master_password: str, salt: bytes, N: int, r: int, p: int, dk_len: int = 32) -> bytes: ...
def hkdf_derive(key: bytes, info: str, length: int = 32) -> bytes: ...
def canonical_ad(ad: Mapping[str, object]) -> bytes: ...
def aead_encrypt(key: bytes, plaintext: bytes, ad: Mapping[str, object], params: AeadParams) -> Encrypted: ...
def aead_decrypt(key: bytes, enc: Encrypted, ad: Mapping[str, object], params: AeadParams) -> bytes: ...
def random_bytes(n: int) -> bytes: ...
def zeroize(b: bytearray) -> None: ...

def derive_vault_keys(master_password: str, kdf_salt: bytes, kdf_params: dict, aead_algo: AeadAlgo) -> dict: ...
def wrap_entry_key(K_content: bytes, entry_id: str, vault_id: str, entry_version: int, KE: bytes, params: AeadParams) -> Encrypted: ...
def unwrap_entry_key(K_content: bytes, entry_id: str, vault_id: str, entry_version: int, enc: Encrypted, params: AeadParams) -> bytes: ...
def encrypt_entry_content(KE: bytes, vault_id: str, entry_id: str, entry_version: int, created_at: int, updated_at: int, plaintext: bytes, params: AeadParams) -> Encrypted: ...
def decrypt_entry_content(KE: bytes, vault_id: str, entry_id: str, entry_version: int, created_at: int, updated_at: int, enc: Encrypted, params: AeadParams) -> bytes: ...
def audit_mac(K_audit: bytes, seq: int, ts: int, action: str, payload: bytes | None, prev_mac: bytes | None, actor: str | None = None) -> bytes: ...
```

## Package: securepwm.vault

Responsibilities: SQLite persistence, schema/migrations, orchestration of crypto for entries, and business rules.

```python
from dataclasses import dataclass
from typing import Optional, Iterable, Protocol

@dataclass
class VaultState:
    vault_id: str
    schema_version: int
    kdf: str
    kdf_params: dict
    kdf_salt: bytes
    aead_algo: str
    created_at: int
    last_unlock_at: Optional[int]

@dataclass
class Entry:
    id: str
    version: int
    created_at: int
    updated_at: int
    deleted: bool
    # ciphertext fields stored in DB
    nonce_content: bytes
    ciphertext_content: bytes
    nonce_ke_wrap: bytes
    wrapped_ke: bytes

class VaultRepo(Protocol):
    def open(self, path: str) -> None: ...
    def init_schema(self, state: VaultState) -> None: ...
    def get_state(self) -> VaultState: ...
    def update_state_last_unlock(self, ts: int) -> None: ...
    def insert_entry(self, e: Entry) -> None: ...
    def update_entry(self, e: Entry) -> None: ...
    def soft_delete_entry(self, entry_id: str) -> None: ...
    def hard_delete_entry(self, entry_id: str) -> None: ...
    def get_entry(self, entry_id: str) -> Optional[Entry]: ...
    def list_entries(self, include_deleted: bool = False) -> Iterable[Entry]: ...
    def begin(self) -> None: ...
    def commit(self) -> None: ...
    def rollback(self) -> None: ...
    def close(self) -> None: ...

class VaultService:
    def __init__(self, repo: VaultRepo): ...
    def init_vault(self, master_password: str, aead_algo: str = "xchacha20poly1305") -> VaultState: ...
    def unlock(self, master_password: str) -> None: ...  # caches KV/subkeys in-memory
    def lock(self) -> None: ...
    def add_entry(self, plaintext: bytes, label: Optional[str] = None) -> str: ...
    def get_entry(self, entry_id: str) -> bytes: ...
    def update_entry(self, entry_id: str, plaintext: bytes) -> None: ...
    def delete_entry(self, entry_id: str, hard: bool = False) -> None: ...
    def list_entry_ids(self, include_deleted: bool = False) -> list[str]: ...
    def rotate_master(self, old_password: str, new_password: str) -> None: ...
    def backup(self, output_path: str) -> None: ...
    def restore(self, input_path: str) -> None: ...
```

## Package: securepwm.audit

```python
from typing import Optional

class AuditService:
    def append(self, action: str, payload: bytes | None, actor: Optional[str] = None) -> None: ...
    def verify(self) -> None: ...  # raises on failure
    def export(self, output_path: str) -> None: ...
    def anchor_snapshot(self) -> bytes: ...  # exported anchor for notarization
```

## Package: securepwm.policy

```python
from dataclasses import dataclass
from typing import Optional

@dataclass
class PolicyConfig:
    min_length: int
    zxcvbn_threshold: int  # 0-4
    max_age_days: int
    prevent_reuse_n: int

class PolicyEngine:
    def __init__(self, cfg: PolicyConfig): ...
    def score_password(self, password: str, user_inputs: Optional[list[str]] = None) -> int: ...
    def check_reuse(self, password_hashes: list[bytes], candidate: str) -> bool: ...
    def check_expiry(self, created_at: int, updated_at: int, now: int) -> bool: ...
    def passgen(self, length: int = 20, allow_symbols: bool = True, avoid_ambiguous: bool = True) -> str: ...
```

## Package: securepwm.recovery

```python
class RecoveryService:
    def init_shares(self, n: int, k: int) -> list[str]: ...  # SLIP-0039 mnemonics
    def print_shares(self, shares: list[str], destination: str | None = None) -> None: ...
    def combine_shares(self, shares: list[str]) -> None: ...  # verifies vault binding
```

## Package: securepwm.totp

```python
class TOTPService:
    def setup(self, issuer: str, account: str) -> str: ...  # returns otpauth:// URI
    def verify(self, token: str) -> bool: ...
    def disable(self) -> None: ...
```

## Package: securepwm.sync (optional)

```python
from typing import Protocol

class SyncProvider(Protocol):
    def push(self, path: str, data: bytes) -> None: ...
    def pull(self, path: str) -> bytes | None: ...
    def list(self, prefix: str) -> list[str]: ...

class SyncService:
    def push(self) -> None: ...
    def pull(self) -> None: ...
    def status(self) -> dict: ...
```

## CLI Wiring (securepwm.cli)

Top-level commands are specified in docs/cli-spec.md; each command maps to one or more service calls with consistent error handling and exit codes.

## Error Types (shared)

Define typed exceptions without leaking secrets:

- `CryptoError`, `KdfError`, `AeadError`, `AuditMacError`, `NonceError`
- `VaultLockedError`, `VaultIntegrityError`, `MigrationError`
- `PolicyViolation`, `TotpError`, `RecoveryError`, `SyncError`

