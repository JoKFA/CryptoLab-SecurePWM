"""
SecurePWM - Cryptography Module (Simplified Educational Version)

This single file contains ALL cryptographic operations for the password manager.
It's designed to be:
- Easy to understand and explain
- Minimal dependencies (only 'cryptography' library)
- Secure (production-grade algorithms)
- Clear (every function does one thing)

Security Architecture:
    1. Master Password → scrypt → Vault Key (32 bytes)
    2. Vault Key → HKDF → Subkeys (content, audit, recovery)
    3. Each entry gets unique random key → AES-GCM encryption
    4. Entry keys are wrapped (encrypted) with content key

Why this is secure:
    - scrypt is memory-hard (resists GPU attacks)
    - AES-256-GCM provides authenticated encryption (can't be tampered)
    - Each entry has unique key (limits damage if one leaks)
    - HMAC chain prevents audit log tampering
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
# CONFIGURATION - Easy to understand and modify
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

    Example:
        >>> salt = os.urandom(16)
        >>> key = derive_vault_key("my_password", salt)
        >>> len(key)
        32
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

    Example:
        >>> vault_key = os.urandom(32)
        >>> keys = derive_subkeys(vault_key)
        >>> len(keys['content_key'])
        32
    """
    def hkdf(info: str) -> bytes:
        """Helper: derive one subkey with given info string."""
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
    }


# =============================================================================
# PART 2: CANONICAL ASSOCIATED DATA (AD) - Per Spec
# =============================================================================

def canonical_ad(ad: dict) -> bytes:
    """
    Convert associated data to canonical JSON bytes (RFC 8785 style).

    Why canonical?
    - Same AD dict ALWAYS produces same bytes
    - Deterministic across platforms
    - Required for decryption to work

    Format:
    - Keys sorted lexicographically
    - No whitespace (compact)
    - UTF-8 encoding without escaping non-ASCII
    - separators=(",", ":") for compact JSON

    Args:
        ad: Dictionary with required fields (depends on context)

    Returns:
        UTF-8 encoded canonical JSON bytes

    Example:
        >>> ad = {"ctx": "entry_content", "entry_id": "123", "vault_id": "456"}
        >>> canonical_ad(ad)
        b'{"ctx":"entry_content","entry_id":"123","vault_id":"456"}'
    """
    # Canonical JSON: sorted keys, compact, UTF-8
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
    - Associated Data: Context is authenticated (prevents misuse)

    Args:
        key: 32-byte encryption key
        plaintext: Data to encrypt
        associated_data: Context dict (MUST include required fields per spec)

    Returns:
        (nonce, ciphertext) tuple
        - nonce: 12 random bytes (must be stored with ciphertext)
        - ciphertext: encrypted data + 16-byte tag

    Example:
        >>> key = os.urandom(32)
        >>> ad = {"ctx": "test", "vault_id": "v1", "entry_id": "e1"}
        >>> nonce, ct = encrypt(key, b"secret", ad)
        >>> len(nonce)
        12
    """
    # Generate random nonce (NEVER reuse with same key!)
    nonce = os.urandom(NONCE_SIZE)

    # Convert associated data to canonical bytes
    ad_bytes = canonical_ad(associated_data)

    # Encrypt with AES-256-GCM
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, ad_bytes)

    return nonce, ciphertext


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, associated_data: dict) -> bytes:
    """
    Decrypt AES-256-GCM ciphertext.

    Args:
        key: Same 32-byte key used for encryption
        nonce: Same nonce used for encryption
        ciphertext: Encrypted data (includes tag)
        associated_data: MUST match encryption exactly, or decryption fails

    Returns:
        Plaintext bytes

    Raises:
        Exception: If tampered, wrong key, or wrong associated data

    Example:
        >>> ad = {"ctx": "test", "vault_id": "v1", "entry_id": "e1"}
        >>> plaintext = decrypt(key, nonce, ct, ad)
        >>> plaintext
        b"secret"
    """
    ad_bytes = canonical_ad(associated_data)

    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, ad_bytes)

    return plaintext


# =============================================================================
# PART 4: VAULT OPERATIONS (High-Level with Full AD Binding)
# =============================================================================

def create_entry_key() -> bytes:
    """
    Generate a random key for one password entry.

    Why unique keys per entry?
    - If one key leaks, other entries are still safe
    - Can delete entries securely (destroy key)

    Returns:
        32-byte random key
    """
    return os.urandom(VAULT_KEY_SIZE)


def wrap_entry_key(
    content_key: bytes,
    entry_key: bytes,
    vault_id: str,
    entry_id: str,
    schema_version: int = 1,
    entry_version: int = 1
) -> Tuple[bytes, bytes]:
    """
    Encrypt (wrap) an entry key using the content key.

    This is "envelope encryption":
    - Entry key encrypts the actual password
    - Content key encrypts the entry key

    Associated Data (prevents context confusion):
    - ctx: "ke_wrap" (identifies this as key wrapping)
    - vault_id: Which vault this belongs to
    - entry_id: Which entry this key is for
    - aead: "aes256gcm" (algorithm used)
    - schema_version: Database schema version
    - entry_version: Entry version (for updates)

    Why full AD binding?
    - Prevents using wrapped key in wrong context
    - Detects if metadata changes
    - Binds to specific vault and entry

    Args:
        content_key: From derive_subkeys()
        entry_key: Random key for this entry
        vault_id: UUID of vault
        entry_id: UUID of entry
        schema_version: Current schema version
        entry_version: Entry version number

    Returns:
        (nonce, wrapped_key) - both must be stored in database
    """
    ad = {
        "ctx": "ke_wrap",
        "vault_id": vault_id,
        "entry_id": entry_id,
        "aead": "aes256gcm",
        "schema_version": schema_version,
        "entry_version": entry_version
    }
    return encrypt(content_key, entry_key, ad)


def unwrap_entry_key(
    content_key: bytes,
    nonce: bytes,
    wrapped_key: bytes,
    vault_id: str,
    entry_id: str,
    schema_version: int = 1,
    entry_version: int = 1
) -> bytes:
    """
    Decrypt (unwrap) an entry key.

    AD MUST match wrap exactly or decryption fails.

    Returns:
        32-byte entry key
    """
    ad = {
        "ctx": "ke_wrap",
        "vault_id": vault_id,
        "entry_id": entry_id,
        "aead": "aes256gcm",
        "schema_version": schema_version,
        "entry_version": entry_version
    }
    return decrypt(content_key, nonce, wrapped_key, ad)


def encrypt_entry_content(
    entry_key: bytes,
    content: bytes,
    vault_id: str,
    entry_id: str,
    created_at: int,
    updated_at: int,
    schema_version: int = 1,
    entry_version: int = 1
) -> Tuple[bytes, bytes]:
    """
    Encrypt password/secret content for an entry.

    Associated Data (prevents rollback/tampering):
    - ctx: "entry_content"
    - vault_id, entry_id: Identity binding
    - aead: Algorithm identifier
    - schema_version, entry_version: Version binding
    - created_at, updated_at: Timestamp binding

    Why include timestamps in AD?
    - Prevents rollback attacks (can't use old ciphertext)
    - Binds ciphertext to its metadata
    - Detects tampering with timestamps

    Args:
        entry_key: Unwrapped entry key
        content: The actual secret (password, note, etc.)
        vault_id: UUID of vault
        entry_id: UUID of entry
        created_at: Creation timestamp (Unix seconds)
        updated_at: Last update timestamp (Unix seconds)
        schema_version: Current schema version
        entry_version: Entry version number

    Returns:
        (nonce, ciphertext) to store in database
    """
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


def decrypt_entry_content(
    entry_key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    vault_id: str,
    entry_id: str,
    created_at: int,
    updated_at: int,
    schema_version: int = 1,
    entry_version: int = 1
) -> bytes:
    """
    Decrypt password/secret content.

    AD MUST match encrypt exactly.

    Returns:
        Plaintext secret
    """
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
# PART 5: AUDIT LOG (Tamper Detection with Full Binding)
# =============================================================================

def compute_audit_mac(
    audit_key: bytes,
    seq: int,
    ts: int,
    action: str,
    prev_mac: Optional[bytes],
    payload: Optional[bytes] = None
) -> bytes:
    """
    Compute HMAC for an audit log entry with full binding.

    How it works:
    - Each entry's MAC includes the previous entry's MAC
    - Creates a chain: MAC1 → MAC2 → MAC3 → ...
    - Any tampering breaks the chain

    What's authenticated (prevents tampering):
    - seq: Sequence number (prevents reordering)
    - ts: Timestamp (prevents backdating)
    - action: What happened (prevents action changes)
    - payload_hash: Hash of encrypted payload if present
    - prev_mac: Previous MAC (creates chain)

    Why include timestamp and payload?
    - Timestamp: Prevents backdating/forward-dating attacks
    - Payload hash: Authenticates any associated data
    - Together: Full audit trail integrity

    Args:
        audit_key: From derive_subkeys()
        seq: Sequence number (1, 2, 3, ...)
        ts: Timestamp (Unix seconds)
        action: What happened (e.g., "ENTRY_ADD", "VAULT_UNLOCK")
        prev_mac: Previous entry's MAC (None for first entry)
        payload: Optional payload bytes to authenticate

    Returns:
        32-byte HMAC

    Example:
        >>> audit_key = os.urandom(32)
        >>> import time
        >>> ts = int(time.time())
        >>> mac1 = compute_audit_mac(audit_key, 1, ts, "INIT", None)
        >>> mac2 = compute_audit_mac(audit_key, 2, ts+1, "ADD", mac1, b"data")
    """
    # Compute payload hash if payload provided
    if payload:
        payload_hash = hashlib.sha256(payload).hexdigest()
    else:
        payload_hash = ""

    # Build message to authenticate (canonical JSON)
    message = {
        "seq": seq,
        "ts": ts,
        "action": action,
        "payload_hash": payload_hash,
        "prev_mac": prev_mac.hex() if prev_mac else ""
    }

    # Use canonical AD (same as AEAD operations)
    message_bytes = canonical_ad(message)

    # Compute HMAC-SHA256
    return hmac.new(audit_key, message_bytes, hashlib.sha256).digest()


def verify_audit_chain(audit_key: bytes, entries: list) -> bool:
    """
    Verify audit log hasn't been tampered with.

    Args:
        audit_key: From derive_subkeys()
        entries: List of dicts with keys: seq, ts, action, payload, mac, prev_mac

    Returns:
        True if chain is valid, False if tampered

    Example:
        >>> entries = [
        ...     {"seq": 1, "ts": 1234, "action": "INIT", "payload": None, "prev_mac": None, "mac": mac1},
        ...     {"seq": 2, "ts": 1235, "action": "ADD", "payload": b"data", "prev_mac": mac1, "mac": mac2}
        ... ]
        >>> verify_audit_chain(audit_key, entries)
        True
    """
    prev_mac = None

    for entry in entries:
        # Recompute MAC
        expected_mac = compute_audit_mac(
            audit_key,
            entry["seq"],
            entry["ts"],
            entry["action"],
            prev_mac,
            entry.get("payload")
        )

        # Check if it matches stored MAC (constant-time comparison)
        if not hmac.compare_digest(expected_mac, entry["mac"]):
            return False  # Tampered!

        prev_mac = entry["mac"]

    return True


# =============================================================================
# PART 5: PASSWORD GENERATION
# =============================================================================

def generate_password(length: int = 20, use_symbols: bool = True) -> str:
    """
    Generate a strong random password.

    Character sets:
    - Uppercase: A-Z (26)
    - Lowercase: a-z (26)
    - Digits: 0-9 (10)
    - Symbols: !@#$%^&*()_+-= (optional, 14)

    Args:
        length: Password length (default 20)
        use_symbols: Include symbols?

    Returns:
        Random password string

    Example:
        >>> pwd = generate_password(16)
        >>> len(pwd)
        16
    """
    import string

    chars = string.ascii_letters + string.digits
    if use_symbols:
        chars += "!@#$%^&*()_+-="

    # Use cryptographically secure random
    # secrets.choice() uses os.urandom()
    import secrets
    return ''.join(secrets.choice(chars) for _ in range(length))


# =============================================================================
# HELPER: Constant-time comparison (prevents timing attacks)
# =============================================================================

def constant_compare(a: bytes, b: bytes) -> bool:
    """
    Compare two byte strings in constant time.

    Why?
    - Normal comparison (a == b) returns False immediately on first mismatch
    - Attacker can measure time to learn how many bytes matched
    - This always takes same time regardless of where mismatch is

    Uses built-in hmac.compare_digest (constant-time).
    """
    return hmac.compare_digest(a, b)


# =============================================================================
# SUMMARY OF WHAT YOU HAVE
# =============================================================================

"""
This single file gives you:

1. MASTER PASSWORD → KEYS
   - derive_vault_key(): scrypt (memory-hard, GPU-resistant)
   - derive_subkeys(): HKDF (domain separation)

2. ENCRYPTION
   - encrypt()/decrypt(): AES-256-GCM (authenticated encryption)
   - Associated Data prevents context confusion

3. ENVELOPE ENCRYPTION
   - wrap_entry_key()/unwrap_entry_key(): Protect entry keys
   - encrypt_entry_content()/decrypt_entry_content(): Protect secrets

4. AUDIT LOG
   - compute_audit_mac(): HMAC chain
   - verify_audit_chain(): Detect tampering

5. PASSWORD GENERATION
   - generate_password(): Cryptographically secure random

Total: ~350 lines, one file, easy to understand!

Next steps:
- vault.py: SQLite database (stores encrypted data)
- cli.py: Command-line interface (user interaction)
- recovery.py: Shamir Secret Sharing (k-of-n backup)
"""
