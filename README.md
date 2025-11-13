# SecurePWM - Zero-Knowledge Password Manager
## Simplified Educational Version

**A minimal, secure, and understandable password manager for academic purposes.**

---

## 🎯 Project Overview

This is a **simplified, educational implementation** of a zero-knowledge password manager. It demonstrates enterprise-grade security concepts in ~1000 lines of clear, well-commented Python code that's easy to understand and explain.

### Why This Project?

- **Educational**: Every line is explained. Perfect for learning cryptography.
- **Secure**: Uses production-grade algorithms (AES-256-GCM, scrypt, HKDF)
- **Simple**: Minimal dependencies, straightforward code
- **Complete**: Includes all security features from the proposal

---

## 🔐 Security Architecture

### Zero-Knowledge Design

**What is "Zero-Knowledge"?**
- Your master password NEVER leaves your device
- All encryption happens locally on your computer
- The database contains ONLY ciphertext (encrypted data)
- Even if someone steals the database file, they get nothing without your master password

### Key Hierarchy

```
Master Password (your secret)
    ↓
[scrypt KDF - memory-hard, GPU-resistant]
    ↓
Vault Key (32 bytes)
    ↓
[HKDF - domain separation]
    ↓
├─ Content Key (encrypts entry keys)
├─ Audit Key (protects log integrity)
└─ Recovery Key (for disaster recovery)
```

### Envelope Encryption (Double Protection)

```
Your Password: "MyGitHubPass123"
    ↓
[Encrypt with Entry Key (unique per entry)]
    ↓
Encrypted Content: 0x3a2f9b... (stored in DB)

Entry Key: 0x7c4d... (32 random bytes)
    ↓
[Encrypt with Content Key]
    ↓
Wrapped Entry Key: 0x8e1a... (stored in DB)
```

**Why double encryption?**
1. Each password has its own unique key (limits damage if one leaks)
2. Can change master password without re-encrypting everything
3. Can rotate algorithms by re-wrapping keys

### Tamper Detection

Every action is logged in an **HMAC-chained audit log**:

```
Entry 1: MAC₁ = HMAC(K_audit, "action=INIT" || prev_mac=null)
Entry 2: MAC₂ = HMAC(K_audit, "action=ADD" || prev_mac=MAC₁)
Entry 3: MAC₃ = HMAC(K_audit, "action=GET" || prev_mac=MAC₂)
```

Any tampering breaks the chain and is detected instantly.

---

## 📦 What's Included

### File Structure (SIMPLE!)

```
securepwm/
├── crypto.py       (~350 lines) - ALL cryptographic operations
├── vault.py        (~300 lines) - SQLite database + operations
├── recovery.py     (~150 lines) - Shamir Secret Sharing
└── cli.py          (~200 lines) - Command-line interface

Total: ~1000 lines of clear, commented code
```

### Dependencies (MINIMAL!)

```
cryptography    - AES-GCM, scrypt, HKDF (industry standard)
shamir-mnemonic - Shamir Secret Sharing (k-of-n recovery)
pytest          - Testing (dev only)
```

**That's it!** No fancy frameworks, no bloat.

---

## 🚀 Quick Start

### Installation

```bash
# Clone repository
cd CryptoLab-SecurePWM

# Install dependencies
pip install -r requirements-simple.txt
```

### Basic Usage

```bash
# 1. Create a new vault
python -m securepwm.cli init

# 2. Add a password (manually)
python -m securepwm.cli add

# 3. Add a generated password
python -m securepwm.cli add --generate --length 20

# 4. List all passwords
python -m securepwm.cli list

# 5. Get a password
python -m securepwm.cli get <entry_id>

# 6. Verify integrity (detect tampering)
python -m securepwm.cli verify

# 7. Create recovery kit (for disaster recovery)
python -m securepwm.cli recovery-create --k 3 --n 5
```

---

## 🔬 Security Features Explained

### 1. **scrypt** (Memory-Hard Key Derivation)

```python
# From crypto.py
def derive_vault_key(password: str, salt: bytes) -> bytes:
    """
    Why scrypt?
    - Memory-hard: Uses ~16 MB RAM
    - Slow: Takes ~250ms (intentionally!)
    - GPU-resistant: Expensive for attackers

    Parameters:
    - N=131072 (2^17): CPU/memory cost
    - r=8: Block size
    - p=1: Parallelization

    This makes brute-force attacks very expensive!
    """
    kdf = Scrypt(salt=salt, length=32, n=2**17, r=8, p=1)
    return kdf.derive(password.encode('utf-8'))
```

### 2. **HKDF** (Key Derivation for Subkeys)

```python
def derive_subkeys(vault_key: bytes) -> Dict[str, bytes]:
    """
    Why HKDF?
    - Creates independent keys from one master key
    - 'info' parameter provides domain separation
    - Each key for different purpose

    Example:
    - content_key = HKDF(vault_key, info="spwm-content-v1")
    - audit_key = HKDF(vault_key, info="spwm-audit-v1")

    These keys are cryptographically independent!
    """
```

### 3. **AES-256-GCM** (Authenticated Encryption)

```python
def encrypt(key: bytes, plaintext: bytes, associated_data: dict):
    """
    Why AES-256-GCM?
    - Confidentiality: Data is encrypted
    - Authenticity: Tampering is detected
    - Associated Data: Context is bound

    Example:
    >>> encrypt(key, b"secret", {"entry_id": "123"})

    The entry_id is authenticated but NOT encrypted.
    This prevents using ciphertext in wrong context!
    """
```

### 4. **Shamir Secret Sharing** (Recovery)

```python
# Generate 3-of-5 shares
shares = generate_recovery_shares(recovery_key, k=3, n=5)

# Properties:
# - Need ANY 3 shares to recover
# - 2 shares reveal NOTHING
# - Can lose 2 shares safely
# - Based on polynomial interpolation
```

---

## 📊 Security Analysis

### What Attacks Does This Resist?

| Attack Type | Protection | How |
|------------|------------|-----|
| **Database theft** | ✅ Strong | Only ciphertext in database |
| **Brute force** | ✅ Strong | scrypt is memory-hard (~16MB per attempt) |
| **GPU attacks** | ✅ Strong | Memory requirements make GPUs expensive |
| **Tampering** | ✅ Strong | HMAC chain detects any modification |
| **Replay attacks** | ✅ Strong | Associated Data binds context |
| **Key reuse** | ✅ Strong | Unique key per entry |

### What Doesn't This Protect Against?

| Attack Type | Protection | Why |
|------------|------------|-----|
| **Keylogger on your PC** | ❌ None | If your OS is compromised, game over |
| **Weak master password** | ⚠️ Partial | scrypt helps, but "password123" is still bad |
| **Memory scraping** | ⚠️ Partial | Keys in RAM while unlocked |
| **Physical access** | ❌ None | Attacker with root access can do anything |

**Bottom line**: This protects against database theft and offline attacks. It can't protect against a fully compromised operating system.

---

## 🧪 Testing the System

### Test Encryption/Decryption

```bash
# Run vault.py directly to see example
python securepwm/vault.py
```

### Test Recovery

```bash
# Run recovery.py directly
python securepwm/recovery.py
```

### Manual Security Tests

```bash
# 1. Create vault and add entries
python -m securepwm.cli init
python -m securepwm.cli add --generate

# 2. Verify audit log is intact
python -m securepwm.cli verify
# Output: ✓ Audit log is intact!

# 3. Tamper with database
# Open ~/.securepwm/vault.db in SQLite editor
# Change a byte in audit_log.mac column

# 4. Verify again
python -m securepwm.cli verify
# Output: ✗ AUDIT LOG HAS BEEN TAMPERED!
```

---

## 📚 Understanding the Code

### Cryptographic Flow (Add Entry)

```python
# 1. User provides password
master_password = "MyMasterPassword"

# 2. Derive vault key (slow by design!)
vault_key = derive_vault_key(master_password, salt)  # ~250ms

# 3. Derive subkeys
keys = derive_subkeys(vault_key)
content_key = keys['content_key']

# 4. Generate random entry key
entry_key = os.urandom(32)  # Unique for this entry

# 5. Encrypt the secret
nonce, ciphertext = encrypt(entry_key, b"my_secret", {"entry_id": "123"})

# 6. Wrap the entry key
key_nonce, wrapped = encrypt(content_key, entry_key, {"purpose": "entry_key"})

# 7. Store in database
# - Only ciphertext and wrapped_key stored
# - No plaintext ever touches disk!
```

### Database Schema (Simple!)

```sql
-- Vault metadata (one row)
CREATE TABLE vault_meta (
    vault_id TEXT,
    salt BLOB,        -- Random, not secret
    created_at INTEGER
);

-- Encrypted entries
CREATE TABLE entries (
    id TEXT PRIMARY KEY,
    key_nonce BLOB,           -- For unwrapping entry key
    key_wrapped BLOB,         -- Encrypted entry key
    content_nonce BLOB,       -- For decrypting content
    content_ciphertext BLOB,  -- Encrypted secret
    created_at INTEGER,
    updated_at INTEGER
);

-- Tamper-evident log
CREATE TABLE audit_log (
    seq INTEGER PRIMARY KEY,
    action TEXT,
    prev_mac BLOB,  -- Links to previous entry
    mac BLOB        -- HMAC of this entry
);
```

---

## 🎓 For Your Project Report

### Key Points to Highlight

1. **Zero-Knowledge Architecture**
   - Explain why storing only ciphertext is secure
   - Compare to traditional password managers (many store plaintext server-side!)

2. **Cryptographic Primitives**
   - scrypt: Memory-hard, resistant to GPUs
   - HKDF: Domain separation
   - AES-GCM: Authenticated encryption
   - HMAC: Audit log chaining

3. **Envelope Encryption**
   - Why double encryption matters
   - How it enables key rotation

4. **Shamir Secret Sharing**
   - k-of-n threshold scheme
   - Mathematical foundation (polynomial interpolation)

5. **Associated Data**
   - Prevents context confusion
   - Binds ciphertext to metadata

### Diagrams You Can Include

1. Key hierarchy flowchart
2. Encryption flow diagram
3. HMAC chain visualization
4. Threat model diagram

---

## 🔧 Extending the Project (Ideas)

Easy additions that maintain simplicity:

1. **Password strength checker**
   ```python
   def check_password_strength(password: str) -> int:
       # Return score 0-4
       # Check length, character classes, common passwords
   ```

2. **Export/Import**
   ```python
   def export_vault(output_file: str):
       # Export encrypted vault (safe to backup)
   ```

3. **Search (without decrypting)**
   ```python
   # Store HMAC(label) for searchable encryption
   label_hash = hmac.new(K_config, label.encode(), sha256).digest()
   ```

4. **Auto-lock timer**
   ```python
   # Lock vault after N minutes of inactivity
   ```

---

## 📖 Additional Resources

### Learn More About the Crypto

- **AES-GCM**: https://en.wikipedia.org/wiki/Galois/Counter_Mode
- **scrypt**: https://en.wikipedia.org/wiki/Scrypt
- **HKDF**: https://tools.ietf.org/html/rfc5869
- **Shamir Secret Sharing**: https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing

### Related Standards

- NIST SP 800-63B (Password Guidelines)
- OWASP Password Storage Cheat Sheet
- Signal Protocol (similar envelope encryption)

---

## 📝 License

MIT License - Free for educational use

---

## 🙋 FAQ

**Q: Is this production-ready?**
A: No, this is simplified for educational purposes. A production system would need:
- Formal security audit
- More extensive testing
- UI/UX improvements
- Backup/sync capabilities

**Q: Why not use library X instead of Y?**
A: We chose minimal, standard libraries to keep the code understandable. In production, you might use different choices.

**Q: Can I use this for real passwords?**
A: While the crypto is sound, this hasn't been audited. For real use, consider established tools like 1Password, BitWarden, or KeePass.

**Q: How do I prove it's secure for my project?**
A:
1. Explain the threat model
2. Walk through the crypto (key derivation, encryption, MAC chain)
3. Show the code is minimal and reviewable
4. Demonstrate tamper detection working
5. Compare to industry standards (NIST, OWASP)

---

## 👏 Credits

Implements concepts from:
- NIST Cryptographic Standards
- OWASP Password Storage Guidelines
- Signal Protocol (envelope encryption)
- Academic research on zero-knowledge systems

Built as an educational project demonstrating secure password management principles.
