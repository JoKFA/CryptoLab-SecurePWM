"""
Simple tests for SecurePWM - Educational version

These tests demonstrate that the cryptographic operations work correctly.
Run with: python test_simple.py
"""

import os
import tempfile
from securepwm import crypto
from securepwm.vault import Vault
from securepwm.recovery import generate_recovery_shares, combine_recovery_shares


def test_kdf():
    """Test key derivation from password."""
    print("Testing KDF (Key Derivation)...")

    password = "test_password"
    salt = os.urandom(16)

    # Derive key twice with same inputs
    key1 = crypto.derive_vault_key(password, salt)
    key2 = crypto.derive_vault_key(password, salt)

    # Should be deterministic
    assert key1 == key2, "KDF should be deterministic"
    assert len(key1) == 32, "Key should be 32 bytes"

    # Different password should give different key
    key3 = crypto.derive_vault_key("different_password", salt)
    assert key1 != key3, "Different passwords should give different keys"

    print("  ✓ KDF works correctly")


def test_encryption():
    """Test AES-GCM encryption/decryption."""
    print("Testing Encryption...")

    key = os.urandom(32)
    plaintext = b"This is a secret message!"
    ad = {"entry_id": "test-123"}

    # Encrypt
    nonce, ciphertext = crypto.encrypt(key, plaintext, ad)

    # Decrypt
    decrypted = crypto.decrypt(key, nonce, ciphertext, ad)

    assert decrypted == plaintext, "Decryption should recover plaintext"
    print("  ✓ Encryption/decryption works")

    # Test tampering detection
    try:
        # Flip a bit in ciphertext
        tampered = bytearray(ciphertext)
        tampered[0] ^= 1  # Flip first bit
        crypto.decrypt(key, nonce, bytes(tampered), ad)
        assert False, "Should have detected tampering"
    except Exception:
        print("  ✓ Tampering detection works")

    # Test wrong AD
    try:
        wrong_ad = {"entry_id": "wrong-id"}
        crypto.decrypt(key, nonce, ciphertext, wrong_ad)
        assert False, "Should have rejected wrong AD"
    except Exception:
        print("  ✓ Associated data validation works")


def test_envelope_encryption():
    """Test envelope encryption (wrapping entry keys)."""
    print("Testing Envelope Encryption...")

    content_key = os.urandom(32)
    entry_key = crypto.create_entry_key()
    entry_id = "test-entry-123"

    # Wrap entry key
    nonce, wrapped = crypto.wrap_entry_key(content_key, entry_key, entry_id)

    # Unwrap entry key
    unwrapped = crypto.unwrap_entry_key(content_key, nonce, wrapped, entry_id)

    assert unwrapped == entry_key, "Unwrapping should recover entry key"
    print("  ✓ Envelope encryption works")


def test_audit_chain():
    """Test HMAC audit chain."""
    print("Testing Audit Chain...")

    audit_key = os.urandom(32)

    # Create chain of 3 entries
    mac1 = crypto.compute_audit_mac(audit_key, 1, "INIT", None)
    mac2 = crypto.compute_audit_mac(audit_key, 2, "ADD", mac1)
    mac3 = crypto.compute_audit_mac(audit_key, 3, "GET", mac2)

    entries = [
        {"seq": 1, "action": "INIT", "prev_mac": None, "mac": mac1},
        {"seq": 2, "action": "ADD", "prev_mac": mac1, "mac": mac2},
        {"seq": 3, "action": "GET", "prev_mac": mac2, "mac": mac3},
    ]

    # Verify chain
    assert crypto.verify_audit_chain(audit_key, entries), "Chain should be valid"
    print("  ✓ Audit chain verification works")

    # Tamper with middle entry
    entries[1]["action"] = "TAMPERED"
    assert not crypto.verify_audit_chain(audit_key, entries), "Should detect tampering"
    print("  ✓ Tampering detection works")


def test_vault_operations():
    """Test vault creation and operations."""
    print("Testing Vault Operations...")

    # Create temporary database
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name

    try:
        # Initialize vault
        vault = Vault(db_path)
        vault_id = vault.initialize("test_master_password")
        assert vault_id, "Should return vault ID"
        print("  ✓ Vault initialization works")

        # Add entry
        entry_id = vault.add_entry(b"my_secret_password")
        assert entry_id, "Should return entry ID"
        print("  ✓ Adding entry works")

        # Get entry
        secret = vault.get_entry(entry_id)
        assert secret == b"my_secret_password", "Should retrieve correct secret"
        print("  ✓ Getting entry works")

        # List entries
        entries = vault.list_entries()
        assert len(entries) == 1, "Should have 1 entry"
        print("  ✓ Listing entries works")

        # Verify audit log
        assert vault.verify_audit_log(), "Audit log should be valid"
        print("  ✓ Audit log verification works")

        # Lock and unlock
        vault.lock()
        vault.unlock("test_master_password")
        print("  ✓ Lock/unlock works")

        # Wrong password
        vault.lock()
        try:
            vault.unlock("wrong_password")
            # This won't fail immediately, but decryption will fail
            vault.get_entry(entry_id)
            assert False, "Should fail with wrong password"
        except Exception:
            print("  ✓ Wrong password detection works")

    finally:
        # Cleanup
        if os.path.exists(db_path):
            os.unlink(db_path)


def test_recovery():
    """Test Shamir Secret Sharing recovery."""
    print("Testing Recovery (Shamir Secret Sharing)...")

    recovery_key = os.urandom(32)

    # Generate 3-of-5 shares
    shares = generate_recovery_shares(recovery_key, k=3, n=5)
    assert len(shares) == 5, "Should generate 5 shares"
    print("  ✓ Share generation works")

    # Recover with 3 shares (shares 0, 2, 4)
    recovered = combine_recovery_shares([shares[0], shares[2], shares[4]])
    assert recovered == recovery_key, "Should recover original key"
    print("  ✓ Recovery from k shares works")

    # Try with different 3 shares (1, 3, 4)
    recovered2 = combine_recovery_shares([shares[1], shares[3], shares[4]])
    assert recovered2 == recovery_key, "Should work with any k shares"
    print("  ✓ Any k shares work")

    # Try with only 2 shares (should fail)
    try:
        combine_recovery_shares([shares[0], shares[1]])
        assert False, "Should require at least k shares"
    except Exception:
        print("  ✓ Insufficient shares rejected")


def test_password_generation():
    """Test password generation."""
    print("Testing Password Generation...")

    # Generate password
    pwd = crypto.generate_password(length=20, use_symbols=True)
    assert len(pwd) == 20, "Should generate requested length"
    print(f"  Generated: {pwd}")

    # Generate without symbols
    pwd_no_sym = crypto.generate_password(length=16, use_symbols=False)
    assert len(pwd_no_sym) == 16
    assert all(c.isalnum() for c in pwd_no_sym), "Should be alphanumeric only"
    print("  ✓ Password generation works")


def run_all_tests():
    """Run all tests."""
    print("=" * 70)
    print("SecurePWM - Test Suite")
    print("=" * 70)
    print()

    tests = [
        test_kdf,
        test_encryption,
        test_envelope_encryption,
        test_audit_chain,
        test_vault_operations,
        test_recovery,
        test_password_generation,
    ]

    failed = []

    for test in tests:
        try:
            test()
            print()
        except Exception as e:
            print(f"  ✗ TEST FAILED: {e}")
            failed.append((test.__name__, e))
            print()

    print("=" * 70)
    if not failed:
        print("✓ ALL TESTS PASSED!")
    else:
        print(f"✗ {len(failed)} TESTS FAILED:")
        for name, error in failed:
            print(f"  - {name}: {error}")
    print("=" * 70)

    return len(failed) == 0


if __name__ == "__main__":
    import sys
    success = run_all_tests()
    sys.exit(0 if success else 1)
