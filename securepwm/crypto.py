"""
SecurePWM - Cryptography Module (Simplified Educational Version)

Security Architecture:
    1. Master Password → scrypt → Vault Key (32 bytes)
    2. Vault Key → HKDF → Subkeys (content, audit, recovery, label)
    3. Each entry gets unique random key → AES-GCM encryption
    4. Entry keys are wrapped (encrypted) with content key
"""

import os
import hmac
import hashlib
import json
from typing import Dict, Tuple, Optional

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# =============================================================================
# CONFIGURATION
# =============================================================================

VAULT_KEY_SIZE = 32      # 256-bit key
NONCE_SIZE = 12          # 96-bit nonce for AES-GCM
TAG_SIZE = 16            # 128-bit authentication tag

# scrypt parameters (tuned for ~250ms on modern CPU)
# N = CPU/memory cost (power of 2), r = block size, p = parallelization
SCRYPT_N = 2**17         # 131072 - uses ~16 MB RAM
SCRYPT_R = 8
SCRYPT_P = 1

# =============================================================================
# PART 1: KEY DERIVATION (Password → Keys)
# =============================================================================

def derive_vault_key(password: str, salt: bytes) -> bytes:
    """
    Derive vault key from master password using scrypt.

    Why scrypt?
    - Memory-hard: Requires lots of RAM, expensive for attackers with GPUs
    - Standard: Well-tested, used by many password managers

    Args:
        password: Master password (user's secret)
        salt: 16-byte random salt (stored in database, NOT secret)

    Returns:
        32-byte vault key
    """
    kdf = Scrypt(
        salt=salt,
        length=VAULT_KEY_SIZE,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
    )
    return kdf.derive(password.encode('utf-8'))


def derive_subkeys(vault_key: bytes) -> Dict[str, bytes]:
    """
    Derive multiple subkeys from vault key using HKDF.

    Why HKDF?
    - Creates cryptographically independent keys from one master key
    - 'info' parameter provides domain separation (each key for different purpose)

    Returns:
        Dictionary with:
        - content_key: For encrypting entry keys
        - audit_key: For audit log HMACs
        - recovery_key: For recovery shares
        - label_key: For hashing searchable labels
    """
    def hkdf(info: str) -> bytes:
        h = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=info.encode('utf-8')
        )
        return h.derive(vault_key)

    return {
        'content_key': hkdf('spwm-content-v1'),
        'audit_key': hkdf('spwm-audit-v1'),
        'recovery_key': hkdf('spwm-recovery-v1'),
        'label_key': hkdf('spwm-label-v1'),
    }

# =============================================================================
# PART 2: CANONICAL ASSOCIATED DATA (AD)
# =============================================================================

def canonical_ad(ad: dict) -> bytes:
    """
    Convert associated data to canonical JSON bytes (RFC 8785 style).

    Why canonical?
    - Same AD dict ALWAYS produces same bytes
    - Deterministic across platforms
    - Required for decryption to work
    """
    json_str = json.dumps(ad, separators=(",", ":"), sort_keys=True, ensure_ascii=False)
    return json_str.encode('utf-8')

# =============================================================================
# PART 3: ENCRYPTION (AES-256-GCM)
# =============================================================================

def encrypt(key: bytes, plaintext: bytes, associated_data: dict) -> Tuple[bytes, bytes]:
    """
    Encrypt data with AES-256-GCM (Authenticated Encryption).

    AES-GCM provides:
    - Confidentiality: Plaintext is hidden
    - Authenticity: Any tampering is detected
    - Associated Data: Context is bound
    """
    nonce = os.urandom(NONCE_SIZE)
    ad_bytes = canonical_ad(associated_data)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, ad_bytes)
    return nonce, ciphertext


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, associated_data: dict) -> bytes:
    """Decrypt AES-256-GCM ciphertext."""
    ad_bytes = canonical_ad(associated_data)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, ad_bytes)

# =============================================================================
# PART 4: VAULT OPERATIONS (High-Level with Full AD Binding)
# =============================================================================

def create_entry_key() -> bytes:
    """Generate a random key for one password entry."""
    return os.urandom(VAULT_KEY_SIZE)


def wrap_entry_key(content_key: bytes, entry_key: bytes, vault_id: str, entry_id: str,
                   schema_version: int = 1, entry_version: int = 1) -> Tuple[bytes, bytes]:
    """Encrypt (wrap) an entry key using the content key."""
    ad = {
        "ctx": "ke_wrap",
        "vault_id": vault_id,
        "entry_id": entry_id,
        "aead": "aes256gcm",
        "schema_version": schema_version,
        "entry_version": entry_version
    }
    return encrypt(content_key, entry_key, ad)


def unwrap_entry_key(content_key: bytes, nonce: bytes, wrapped_key: bytes, vault_id: str,
                     entry_id: str, schema_version: int = 1, entry_version: int = 1) -> bytes:
    """Decrypt (unwrap) an entry key."""
    ad = {
        "ctx": "ke_wrap",
        "vault_id": vault_id,
        "entry_id": entry_id,
        "aead": "aes256gcm",
        "schema_version": schema_version,
        "entry_version": entry_version
    }
    return decrypt(content_key, nonce, wrapped_key, ad)


def encrypt_entry_content(entry_key: bytes, content: bytes, vault_id: str, entry_id: str,
                          created_at: int, updated_at: int, schema_version: int = 1,
                          entry_version: int = 1) -> Tuple[bytes, bytes]:
    """Encrypt password/secret content for an entry."""
    ad = {
        "ctx": "entry_content",
        "vault_id": vault_id,
        "entry_id": entry_id,
        "aead": "aes256gcm",
        "schema_version": schema_version,
        "entry_version": entry_version,
        "created_at": created_at,
        "updated_at": updated_at
    }
    return encrypt(entry_key, content, ad)


def decrypt_entry_content(entry_key: bytes, nonce: bytes, ciphertext: bytes, vault_id: str,
                          entry_id: str, created_at: int, updated_at: int,
                          schema_version: int = 1, entry_version: int = 1) -> bytes:
    """Decrypt password/secret content."""
    ad = {
        "ctx": "entry_content",
        "vault_id": vault_id,
        "entry_id": entry_id,
        "aead": "aes256gcm",
        "schema_version": schema_version,
        "entry_version": entry_version,
        "created_at": created_at,
        "updated_at": updated_at
    }
    return decrypt(entry_key, nonce, ciphertext, ad)

# =============================================================================
# PART 5: SEARCHABLE LABEL HASHING
# =============================================================================

def hash_label(label_key: bytes, label: str) -> bytes:
    """
    Create a searchable hash of a label (username or site).
    This allows exact-match searching without storing plaintext in a reversible way.
    """
    return hmac.new(label_key, label.lower().encode('utf-8'), hashlib.sha256).digest()

# =============================================================================
# PART 6: AUDIT LOG (Tamper Detection)
# =============================================================================

def compute_audit_mac(audit_key: bytes, seq: int, ts: int, action: str,
                      prev_mac: Optional[bytes], payload: Optional[bytes] = None) -> bytes:
    """
    Compute HMAC for an audit log entry with full binding.

    How it works:
    - Each entry's MAC includes the previous entry's MAC
    - Creates a chain: MAC1 → MAC2 → MAC3 → ...
    - Any tampering breaks the chain
    """
    payload_hash = hashlib.sha256(payload).hexdigest() if payload else ""
    message = {
        "seq": seq,
        "ts": ts,
        "action": action,
        "payload_hash": payload_hash,
        "prev_mac": prev_mac.hex() if prev_mac else ""
    }
    message_bytes = canonical_ad(message)
    return hmac.new(audit_key, message_bytes, hashlib.sha256).digest()


def verify_audit_chain(audit_key: bytes, entries: list) -> bool:
    """Verify audit log hasn't been tampered with."""
    prev_mac = None
    for entry in entries:
        expected_mac = compute_audit_mac(
            audit_key, entry["seq"], entry["ts"],
            entry["action"], prev_mac, entry.get("payload")
        )
        if not hmac.compare_digest(expected_mac, entry["mac"]):
            return False
        prev_mac = entry["mac"]
    return True

# =============================================================================
# PART 7: PASSWORD GENERATION
# =============================================================================

def generate_password(length: int = 20, use_symbols: bool = True) -> str:
    """Generate a strong random password using cryptographically secure random."""
    import string
    import secrets
    chars = string.ascii_letters + string.digits
    if use_symbols:
        chars += "!@#$%^&*()_+-="
    return ''.join(secrets.choice(chars) for _ in range(length))


def constant_compare(a: bytes, b: bytes) -> bool:
    """Compare two byte strings in constant time (prevents timing attacks)."""
    return hmac.compare_digest(a, b)