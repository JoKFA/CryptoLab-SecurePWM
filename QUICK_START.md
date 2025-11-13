# SecurePWM - Quick Start Guide

## 🚀 Get Started in 5 Minutes

### Step 1: Install Dependencies

```bash
pip install cryptography shamir-mnemonic pytest
```

**That's it!** Only 2 dependencies for the core system.

---

### Step 2: Run the Demo

```bash
python demo.py
```

This interactive demo will show you:
- How the encryption works
- Envelope encryption (double protection)
- Audit log tamper detection
- Complete vault operations
- Recovery system
- Password generation

---

### Step 3: Run Tests

```bash
python test_simple.py
```

This runs comprehensive tests on all cryptographic operations.

---

### Step 4: Try the CLI

```bash
# Create a new vault
python -m securepwm.cli init

# Add a password (generated)
python -m securepwm.cli add --generate --length 20

# List all entries
python -m securepwm.cli list

# Get a specific entry
python -m securepwm.cli get <entry_id>

# Verify integrity
python -m securepwm.cli verify

# Create recovery kit
python -m securepwm.cli recovery-create --k 3 --n 5
```

---

## 📁 Project Structure

```
CryptoLab-SecurePWM/
│
├── securepwm/              # Main package
│   ├── crypto.py           # ALL crypto operations (~350 lines)
│   ├── vault.py            # Database + vault logic (~300 lines)
│   ├── recovery.py         # Shamir Secret Sharing (~150 lines)
│   └── cli.py              # Command-line interface (~200 lines)
│
├── demo.py                 # Interactive demo
├── test_simple.py          # Test suite
├── README-SIMPLIFIED.md    # Full documentation
├── QUICK_START.md          # This file
└── requirements-simple.txt # Dependencies
```

**Total: ~1000 lines of clear, commented code**

---

## 🔐 Security Guarantees

### What This Protects Against

✅ **Database theft** - Only ciphertext stored
✅ **Brute force attacks** - scrypt is memory-hard
✅ **Tampering** - Audit log detects any modification
✅ **Key reuse** - Each entry has unique key
✅ **Context confusion** - Associated Data binds ciphertext to metadata

### What This Doesn't Protect Against

❌ **Compromised OS** - If attacker has root, game over
❌ **Keylogger** - Can't protect against hardware keylogger
❌ **Weak password** - "password123" is still bad
❌ **Physical access** - Attacker with physical access can do anything

---

## 📊 Code Overview

### crypto.py (The Heart of Security)

```python
# Part 1: Key Derivation
derive_vault_key()       # Password → Key (scrypt)
derive_subkeys()         # Key → Subkeys (HKDF)

# Part 2: Encryption
encrypt()                # AES-256-GCM encryption
decrypt()                # AES-256-GCM decryption

# Part 3: Vault Operations
wrap_entry_key()         # Encrypt entry key
unwrap_entry_key()       # Decrypt entry key
encrypt_entry_content()  # Encrypt password
decrypt_entry_content()  # Decrypt password

# Part 4: Audit Log
compute_audit_mac()      # HMAC for log entry
verify_audit_chain()     # Check log integrity

# Part 5: Utilities
generate_password()      # Secure random passwords
```

### vault.py (Database & Operations)

```python
class Vault:
    initialize()         # Create new vault
    unlock()             # Unlock with master password
    lock()               # Clear keys from memory
    add_entry()          # Store encrypted password
    get_entry()          # Retrieve and decrypt password
    list_entries()       # List all entries
    delete_entry()       # Delete entry
    verify_audit_log()   # Check log integrity
```

### recovery.py (Disaster Recovery)

```python
generate_recovery_shares()  # Split key into n shares
combine_recovery_shares()   # Recover from k shares
print_recovery_kit()        # Format for printing
```

---

## 🎓 For Your Project Report

### Key Concepts to Explain

1. **Zero-Knowledge Architecture**
   ```
   User's Device          Database Server
   ┌──────────┐           ┌──────────┐
   │ Password │ ──────►   │          │
   │    ↓     │           │ Only     │
   │  scrypt  │           │ Encrypted│
   │    ↓     │           │ Data     │
   │   Keys   │           │          │
   │    ↓     │           │ No Keys! │
   │ Encrypt  │           │          │
   │    ↓     │           │          │
   │Ciphertext│ ──────►   │ Stored   │
   └──────────┘           └──────────┘
   ```

2. **Envelope Encryption**
   ```
   Password "MyPass123"
       ↓
   [Encrypt with Entry Key (random)]
       ↓
   Encrypted Content (in DB)

   Entry Key
       ↓
   [Encrypt with Content Key (from master password)]
       ↓
   Wrapped Entry Key (in DB)
   ```

3. **Audit Chain**
   ```
   Entry 1: MAC₁ = HMAC(data₁ || prev=null)
                ↓
   Entry 2: MAC₂ = HMAC(data₂ || prev=MAC₁)
                ↓
   Entry 3: MAC₃ = HMAC(data₃ || prev=MAC₂)

   Tamper with Entry 2 → MAC₂ changes → MAC₃ verification fails!
   ```

4. **Shamir Secret Sharing**
   ```
   k-of-n threshold scheme
   Example: 3-of-5

   Secret → Split into 5 shares

   Any 3 shares → Recover secret ✓
   Only 2 shares → Learn NOTHING ✓
   Can lose 2 shares safely ✓
   ```

---

## 🔬 Testing Security Claims

### Test 1: Encryption Works
```bash
python test_simple.py
# Look for: ✓ Encryption/decryption works
```

### Test 2: Tampering Detected
```bash
python test_simple.py
# Look for: ✓ Tampering detection works
```

### Test 3: Audit Chain Integrity
```bash
python -m securepwm.cli init
python -m securepwm.cli add --generate
python -m securepwm.cli verify
# Should say: ✓ Audit log is intact!

# Now manually tamper with database
# Open ~/.securepwm/vault.db with SQLite editor
# Change a byte in audit_log.mac

python -m securepwm.cli verify
# Should say: ✗ AUDIT LOG HAS BEEN TAMPERED!
```

### Test 4: Recovery Works
```bash
python test_simple.py
# Look for: ✓ Recovery from k shares works
```

---

## 📝 Common Questions

**Q: How much code do I need to understand?**
A: Start with `securepwm/crypto.py` (~350 lines). That's the core. Everything else builds on it.

**Q: Can I explain this in my presentation?**
A: Yes! The demo.py shows everything visually. Run it and screenshot the output.

**Q: Is this secure enough for a project?**
A: Absolutely! The crypto is production-grade. It's simplified for clarity, not weakened.

**Q: How do I prove it's secure?**
A:
1. Show the threat model (what attacks it resists)
2. Walk through the key derivation (scrypt parameters)
3. Explain envelope encryption (why double encryption)
4. Demonstrate tampering detection (run tests)
5. Compare to standards (NIST, OWASP)

**Q: What if I need to extend it?**
A: Easy! The code is modular:
- Add password strength checker → `crypto.py`
- Add search → `vault.py`
- Add sync → new file `sync.py`
- Add UI → new file `gui.py`

---

## 🎯 Next Steps

1. **Read** the code in `securepwm/crypto.py`
2. **Run** the demo: `python demo.py`
3. **Test** it: `python test_simple.py`
4. **Use** the CLI: `python -m securepwm.cli init`
5. **Understand** the README: `README-SIMPLIFIED.md`

---

## 💡 Tips for Your Report

### Introduction
- Explain the problem: Password reuse, weak passwords, database breaches
- Your solution: Zero-knowledge password manager
- Key innovation: Even server admin can't access passwords

### Technical Details
- Key derivation: scrypt (memory-hard, GPU-resistant)
- Encryption: AES-256-GCM (authenticated, prevents tampering)
- Architecture: Envelope encryption (double protection)
- Integrity: HMAC chain (detect any modification)
- Recovery: Shamir Secret Sharing (k-of-n backup)

### Implementation
- Language: Python 3.12+
- Dependencies: Minimal (cryptography, shamir-mnemonic)
- Lines of code: ~1000 (easy to audit)
- Structure: 4 files (crypto, vault, recovery, CLI)

### Testing
- Unit tests: All crypto functions
- Integration tests: Full vault operations
- Security tests: Tampering detection, wrong password
- Property tests: Recovery with different share combinations

### Conclusion
- Achieved zero-knowledge architecture
- Production-grade cryptography
- Minimal, auditable codebase
- Demonstrates all security concepts from proposal

---

## 📚 References for Report

- NIST SP 800-63B: Digital Identity Guidelines
- OWASP: Password Storage Cheat Sheet
- RFC 5869: HKDF (HMAC-based Key Derivation)
- RFC 7539: ChaCha20 and Poly1305 (alternative AEAD)
- Shamir, A. (1979): How to Share a Secret

---

**You're ready to go!** 🚀

Run `python demo.py` to see everything in action.
