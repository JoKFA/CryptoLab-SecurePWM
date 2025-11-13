"""
SecurePWM - Interactive Demo

This script demonstrates all features of the password manager.
Run with: python demo.py
"""

import os
import tempfile
from securepwm import crypto
from securepwm.vault import Vault
from securepwm.recovery import generate_recovery_shares, print_recovery_kit


def print_section(title):
    """Print formatted section header."""
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70 + "\n")


def demo_crypto_basics():
    """Demonstrate basic cryptographic operations."""
    print_section("1. Cryptographic Basics")

    # Key Derivation
    print("📌 Key Derivation (scrypt)")
    print("   Converting password to cryptographic key...")
    password = "MyMasterPassword123!"
    salt = os.urandom(16)
    vault_key = crypto.derive_vault_key(password, salt)
    print(f"   Password: {password}")
    print(f"   Salt: {salt.hex()[:32]}...")
    print(f"   Derived Key: {vault_key.hex()[:32]}...")
    print("   ✓ This process is intentionally slow (~250ms) to resist attacks")

    # Subkeys
    print("\n📌 Subkey Derivation (HKDF)")
    print("   Creating specialized keys for different purposes...")
    subkeys = crypto.derive_subkeys(vault_key)
    print(f"   Content Key: {subkeys['content_key'].hex()[:32]}...")
    print(f"   Audit Key: {subkeys['audit_key'].hex()[:32]}...")
    print(f"   Recovery Key: {subkeys['recovery_key'].hex()[:32]}...")
    print("   ✓ Each key is cryptographically independent")

    # Encryption
    print("\n📌 Authenticated Encryption (AES-256-GCM)")
    print("   Encrypting a secret with authenticated metadata...")
    key = os.urandom(32)
    secret = b"My GitHub Password: gh_123abc456def"
    ad = {"entry_id": "abc-123", "purpose": "demo"}

    nonce, ciphertext = crypto.encrypt(key, secret, ad)
    print(f"   Plaintext: {secret}")
    print(f"   Nonce: {nonce.hex()}")
    print(f"   Ciphertext: {ciphertext.hex()[:64]}...")
    print(f"   Associated Data: {ad}")

    decrypted = crypto.decrypt(key, nonce, ciphertext, ad)
    print(f"   Decrypted: {decrypted}")
    print("   ✓ Any tampering with ciphertext or AD will be detected")


def demo_envelope_encryption():
    """Demonstrate envelope encryption."""
    print_section("2. Envelope Encryption (Double Protection)")

    print("📌 Why Double Encryption?")
    print("   1. Your password is encrypted with a unique Entry Key")
    print("   2. The Entry Key itself is encrypted with the Content Key")
    print("   3. Only ciphertext is stored in the database")
    print()

    content_key = os.urandom(32)
    entry_id = "entry-456"

    # Step 1: Create entry key
    print("Step 1: Generate random Entry Key")
    entry_key = crypto.create_entry_key()
    print(f"   Entry Key: {entry_key.hex()[:32]}...")

    # Step 2: Encrypt secret with entry key
    print("\nStep 2: Encrypt secret with Entry Key")
    secret = b"SuperSecretPassword123!"
    content_nonce, content_ct = crypto.encrypt_entry_content(
        entry_key, secret, entry_id
    )
    print(f"   Secret: {secret}")
    print(f"   Encrypted: {content_ct.hex()[:48]}...")

    # Step 3: Wrap entry key with content key
    print("\nStep 3: Wrap Entry Key with Content Key")
    key_nonce, wrapped_key = crypto.wrap_entry_key(
        content_key, entry_key, entry_id
    )
    print(f"   Wrapped Entry Key: {wrapped_key.hex()[:48]}...")

    # What's stored in database
    print("\n💾 What's Stored in Database:")
    print(f"   - Wrapped Entry Key: {wrapped_key.hex()[:32]}...")
    print(f"   - Encrypted Content: {content_ct.hex()[:32]}...")
    print(f"   - Nonces (not secret): {key_nonce.hex()}, {content_nonce.hex()[:16]}...")
    print("   - NO plaintext!")

    # Decryption process
    print("\n🔓 Decryption Process:")
    print("   1. Unwrap Entry Key using Content Key")
    unwrapped_key = crypto.unwrap_entry_key(content_key, key_nonce, wrapped_key, entry_id)
    print(f"      Unwrapped Key: {unwrapped_key.hex()[:32]}...")

    print("   2. Decrypt Content using Entry Key")
    decrypted = crypto.decrypt_entry_content(
        unwrapped_key, content_nonce, content_ct, entry_id
    )
    print(f"      Decrypted Secret: {decrypted}")
    print("   ✓ Got our secret back!")


def demo_audit_log():
    """Demonstrate tamper-evident audit logging."""
    print_section("3. Tamper-Evident Audit Log")

    print("📌 HMAC Chain Concept:")
    print("   Each log entry includes a MAC (Message Authentication Code)")
    print("   that depends on the previous entry's MAC, creating a chain.")
    print()

    audit_key = os.urandom(32)

    # Build a chain
    print("Building audit chain...")
    actions = ["VAULT_INIT", "ENTRY_ADD", "ENTRY_GET", "ENTRY_UPDATE", "ENTRY_DELETE"]
    prev_mac = None
    entries = []

    for i, action in enumerate(actions, 1):
        mac = crypto.compute_audit_mac(audit_key, i, action, prev_mac)
        entries.append({
            "seq": i,
            "action": action,
            "prev_mac": prev_mac,
            "mac": mac
        })
        print(f"   {i}. {action:15} → MAC: {mac.hex()[:32]}...")
        prev_mac = mac

    # Verify chain
    print("\n🔍 Verifying Chain...")
    if crypto.verify_audit_chain(audit_key, entries):
        print("   ✓ Chain is VALID - No tampering detected")
    else:
        print("   ✗ Chain is INVALID - Tampering detected!")

    # Tamper with it
    print("\n🔨 Simulating Tampering...")
    print("   Changing entry 3 from 'ENTRY_GET' to 'HACKED'...")
    entries[2]["action"] = "HACKED"

    if crypto.verify_audit_chain(audit_key, entries):
        print("   ✗ Chain is still valid (this shouldn't happen!)")
    else:
        print("   ✓ TAMPERING DETECTED! Chain is now invalid.")
        print("   Any modification breaks the chain!")


def demo_vault_full():
    """Demonstrate full vault operations."""
    print_section("4. Complete Vault Operations")

    # Create temporary vault
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name

    try:
        # Initialize
        print("📌 Creating New Vault")
        master_password = "DemoMasterPassword123!"
        vault = Vault(db_path)
        vault_id = vault.initialize(master_password)
        print(f"   ✓ Vault created: {vault_id}")
        print(f"   ✓ Database: {db_path}")

        # Add entries
        print("\n📌 Adding Password Entries")
        entries_added = []
        secrets = [
            (b"github.com: MyGitHubPassword", "GitHub"),
            (b"gmail.com: MyEmailPassword", "Email"),
            (b"bank.com: MyBankingPassword", "Banking"),
        ]

        for secret, label in secrets:
            entry_id = vault.add_entry(secret)
            entries_added.append((entry_id, label))
            print(f"   ✓ Added {label}: {entry_id[:8]}...")

        # List entries
        print("\n📌 Listing All Entries")
        entries = vault.list_entries()
        for entry in entries:
            from datetime import datetime
            created = datetime.fromtimestamp(entry['created_at']).strftime('%Y-%m-%d %H:%M:%S')
            print(f"   - {entry['id'][:8]}... (created: {created})")

        # Retrieve entry
        print("\n📌 Retrieving Entry")
        entry_id, label = entries_added[0]
        secret = vault.get_entry(entry_id)
        print(f"   Entry: {entry_id[:8]}...")
        print(f"   Secret: {secret.decode('utf-8')}")

        # Verify audit log
        print("\n📌 Verifying Audit Log")
        if vault.verify_audit_log():
            print("   ✓ Audit log is intact!")
            print("   All operations have been properly logged.")
        else:
            print("   ✗ Audit log has been tampered!")

        # Lock vault
        print("\n📌 Locking Vault")
        vault.lock()
        print("   ✓ Vault locked (keys cleared from memory)")

        # Unlock again
        print("\n📌 Unlocking Vault")
        vault.unlock(master_password)
        print("   ✓ Vault unlocked")

    finally:
        # Cleanup
        if os.path.exists(db_path):
            os.unlink(db_path)
            print(f"\n   Cleaned up demo database")


def demo_recovery():
    """Demonstrate recovery system."""
    print_section("5. Disaster Recovery (Shamir Secret Sharing)")

    print("📌 k-of-n Secret Sharing")
    print("   Split a secret into n shares, need k to recover")
    print("   Example: 3-of-5 scheme")
    print()

    # Generate recovery key
    recovery_key = os.urandom(32)
    print(f"   Original Key: {recovery_key.hex()[:32]}...")

    # Generate shares
    print("\n   Generating 5 shares (need any 3 to recover)...")
    shares = generate_recovery_shares(recovery_key, k=3, n=5)

    for i, share in enumerate(shares, 1):
        words = " ".join(share[:5])  # Show first 5 words
        print(f"   Share {i}: {words}...")

    # Recovery scenario 1
    print("\n📌 Recovery Scenario 1: Using shares 1, 3, 5")
    from securepwm.recovery import combine_recovery_shares
    recovered = combine_recovery_shares([shares[0], shares[2], shares[4]])
    print(f"   Recovered Key: {recovered.hex()[:32]}...")
    if recovered == recovery_key:
        print("   ✓ Successfully recovered!")
    else:
        print("   ✗ Recovery failed!")

    # Recovery scenario 2
    print("\n📌 Recovery Scenario 2: Using shares 2, 4, 5")
    recovered2 = combine_recovery_shares([shares[1], shares[3], shares[4]])
    if recovered2 == recovery_key:
        print("   ✓ Successfully recovered with different shares!")
    else:
        print("   ✗ Recovery failed!")

    # Insufficient shares
    print("\n📌 Insufficient Shares: Trying with only 2 shares")
    try:
        combine_recovery_shares([shares[0], shares[1]])
        print("   ✗ Should have failed!")
    except Exception as e:
        print("   ✓ Correctly rejected (need at least 3 shares)")


def demo_password_generation():
    """Demonstrate password generation."""
    print_section("6. Secure Password Generation")

    print("📌 Generating Strong Passwords")
    print()

    configs = [
        (16, True, "Default (16 chars, with symbols)"),
        (20, True, "Long (20 chars, with symbols)"),
        (12, False, "No symbols (alphanumeric only)"),
        (32, True, "Very long (32 chars)"),
    ]

    for length, use_symbols, description in configs:
        pwd = crypto.generate_password(length, use_symbols)
        print(f"   {description}:")
        print(f"   → {pwd}")
        print()


def main():
    """Run complete demo."""
    print("\n" + "=" * 70)
    print("  SecurePWM - Complete Interactive Demo")
    print("  Educational Zero-Knowledge Password Manager")
    print("=" * 70)

    demos = [
        ("Cryptographic Basics", demo_crypto_basics),
        ("Envelope Encryption", demo_envelope_encryption),
        ("Audit Log", demo_audit_log),
        ("Vault Operations", demo_vault_full),
        ("Recovery System", demo_recovery),
        ("Password Generation", demo_password_generation),
    ]

    print("\nThis demo will show you:")
    for i, (name, _) in enumerate(demos, 1):
        print(f"   {i}. {name}")

    input("\nPress Enter to start the demo...")

    for name, demo_func in demos:
        try:
            demo_func()
            input("\n→ Press Enter to continue...")
        except Exception as e:
            print(f"\n✗ Demo failed: {e}")
            import traceback
            traceback.print_exc()

    print_section("Demo Complete!")
    print("✓ You've seen all the key features of SecurePWM")
    print()
    print("Next steps:")
    print("   1. Run tests: python test_simple.py")
    print("   2. Try the CLI: python -m securepwm.cli init")
    print("   3. Read the code in securepwm/crypto.py")
    print("   4. Check out README-SIMPLIFIED.md")
    print()


if __name__ == "__main__":
    main()
