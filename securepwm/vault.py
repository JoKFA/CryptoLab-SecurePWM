"""
SecurePWM - Vault Module (Simplified)

This file handles:
- SQLite database (stores encrypted data)
- Vault initialization
- Adding/retrieving/deleting entries
- Audit logging

Database structure:
- vault_meta: Vault configuration (salt, creation time)
- entries: Encrypted password entries
- audit_log: Tamper-evident log of all operations
"""

import sqlite3
import os
import time
import uuid
from typing import Optional, List, Dict

from . import crypto


# =============================================================================
# DATABASE SCHEMA
# =============================================================================

SCHEMA = """
-- Vault metadata (one row)
CREATE TABLE IF NOT EXISTS vault_meta (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    vault_id TEXT NOT NULL,
    salt BLOB NOT NULL,
    created_at INTEGER NOT NULL
);

-- Password entries (all encrypted)
CREATE TABLE IF NOT EXISTS entries (
    id TEXT PRIMARY KEY,
    -- Entry key (wrapped/encrypted)
    key_nonce BLOB NOT NULL,
    key_wrapped BLOB NOT NULL,
    -- Content (encrypted)
    content_nonce BLOB NOT NULL,
    content_ciphertext BLOB NOT NULL,
    -- Metadata
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    deleted INTEGER DEFAULT 0
);

-- Audit log (tamper-evident chain)
CREATE TABLE IF NOT EXISTS audit_log (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp INTEGER NOT NULL,
    action TEXT NOT NULL,
    prev_mac BLOB,
    mac BLOB NOT NULL
);
"""


# =============================================================================
# VAULT CLASS
# =============================================================================

class Vault:
    """
    Main vault class - handles all password management operations.

    Usage:
        # Create new vault
        vault = Vault("my_vault.db")
        vault.initialize("master_password")

        # Later: unlock vault
        vault = Vault("my_vault.db")
        vault.unlock("master_password")

        # Add entry
        entry_id = vault.add_entry(b"my_secret_password")

        # Retrieve entry
        secret = vault.get_entry(entry_id)

        # Lock when done
        vault.lock()
    """

    def __init__(self, db_path: str):
        """
        Initialize vault (doesn't unlock it yet).

        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path
        self.conn: Optional[sqlite3.Connection] = None
        self.vault_id: Optional[str] = None
        self.salt: Optional[bytes] = None

        # Keys (only present when unlocked)
        self.vault_key: Optional[bytes] = None
        self.content_key: Optional[bytes] = None
        self.audit_key: Optional[bytes] = None
        self.recovery_key: Optional[bytes] = None

    def initialize(self, master_password: str) -> str:
        """
        Create a new vault with master password.

        This:
        1. Creates database
        2. Generates random salt
        3. Derives keys from master password
        4. Records initialization in audit log

        Args:
            master_password: User's master password

        Returns:
            Vault ID (UUID)

        Example:
            >>> vault = Vault("test.db")
            >>> vault_id = vault.initialize("MySecurePassword123!")
        """
        # Connect to database
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row  # Access columns by name

        # Create tables
        self.conn.executescript(SCHEMA)

        # Generate salt and vault ID
        self.salt = os.urandom(16)
        self.vault_id = str(uuid.uuid4())

        # Save vault metadata
        self.conn.execute(
            "INSERT INTO vault_meta (id, vault_id, salt, created_at) VALUES (1, ?, ?, ?)",
            (self.vault_id, self.salt, int(time.time()))
        )
        self.conn.commit()

        # Derive keys
        self._derive_keys(master_password)

        # Log initialization
        self._audit("VAULT_INIT")

        return self.vault_id

    def unlock(self, master_password: str) -> None:
        """
        Unlock existing vault with master password.

        Args:
            master_password: User's master password

        Raises:
            Exception: If password is wrong (decryption will fail later)

        Example:
            >>> vault = Vault("test.db")
            >>> vault.unlock("MySecurePassword123!")
        """
        # Connect to database
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row

        # Load vault metadata
        row = self.conn.execute("SELECT * FROM vault_meta WHERE id = 1").fetchone()
        if not row:
            raise Exception("Vault not initialized")

        self.vault_id = row['vault_id']
        self.salt = row['salt']

        # Derive keys
        self._derive_keys(master_password)

        # Log unlock
        self._audit("VAULT_UNLOCK")

    def lock(self) -> None:
        """
        Lock vault (clear keys from memory).

        SECURITY: This clears sensitive keys, but Python may keep copies
        in memory. Best practice: lock when not actively using vault.

        Example:
            >>> vault.lock()
        """
        # Zero out keys (best effort)
        if self.vault_key:
            self.vault_key = None
        if self.content_key:
            self.content_key = None
        if self.audit_key:
            self.audit_key = None
        if self.recovery_key:
            self.recovery_key = None

        # Close database
        if self.conn:
            self.conn.close()
            self.conn = None

    def add_entry(self, secret: bytes, label: Optional[str] = None) -> str:
        """
        Add a new password entry.

        Process:
        1. Generate random entry key
        2. Encrypt secret with entry key
        3. Wrap (encrypt) entry key with content key
        4. Store everything in database
        5. Log action

        Args:
            secret: The password/secret to store
            label: Optional human-readable label (NOT ENCRYPTED - use carefully!)

        Returns:
            Entry ID (UUID)

        Example:
            >>> entry_id = vault.add_entry(b"MyPassword123!", label="GitHub")
        """
        self._require_unlocked()

        # Generate entry ID and key
        entry_id = str(uuid.uuid4())
        entry_key = crypto.create_entry_key()

        # Encrypt the secret content
        content_nonce, content_ct = crypto.encrypt_entry_content(
            entry_key, secret, entry_id
        )

        # Wrap the entry key
        key_nonce, key_wrapped = crypto.wrap_entry_key(
            self.content_key, entry_key, entry_id
        )

        # Store in database
        now = int(time.time())
        self.conn.execute(
            """
            INSERT INTO entries (id, key_nonce, key_wrapped, content_nonce,
                                content_ciphertext, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (entry_id, key_nonce, key_wrapped, content_nonce, content_ct, now, now)
        )
        self.conn.commit()

        # Log action
        self._audit("ENTRY_ADD")

        return entry_id

    def get_entry(self, entry_id: str) -> bytes:
        """
        Retrieve and decrypt a password entry.

        Process:
        1. Load encrypted data from database
        2. Unwrap entry key
        3. Decrypt content with entry key
        4. Log access

        Args:
            entry_id: UUID of entry

        Returns:
            Decrypted secret (bytes)

        Raises:
            Exception: If entry not found or decryption fails

        Example:
            >>> secret = vault.get_entry(entry_id)
            >>> secret
            b"MyPassword123!"
        """
        self._require_unlocked()

        # Load entry from database
        row = self.conn.execute(
            "SELECT * FROM entries WHERE id = ? AND deleted = 0",
            (entry_id,)
        ).fetchone()

        if not row:
            raise Exception(f"Entry {entry_id} not found")

        # Unwrap entry key
        entry_key = crypto.unwrap_entry_key(
            self.content_key,
            row['key_nonce'],
            row['key_wrapped'],
            entry_id
        )

        # Decrypt content
        secret = crypto.decrypt_entry_content(
            entry_key,
            row['content_nonce'],
            row['content_ciphertext'],
            entry_id
        )

        # Log access
        self._audit("ENTRY_GET")

        return secret

    def list_entries(self) -> List[Dict]:
        """
        List all entries (metadata only, not decrypted).

        Returns:
            List of dicts with: id, created_at, updated_at

        Example:
            >>> entries = vault.list_entries()
            >>> for e in entries:
            ...     print(e['id'], e['created_at'])
        """
        self._require_unlocked()

        rows = self.conn.execute(
            "SELECT id, created_at, updated_at FROM entries WHERE deleted = 0"
        ).fetchall()

        return [dict(row) for row in rows]

    def delete_entry(self, entry_id: str, hard: bool = False) -> None:
        """
        Delete an entry.

        Args:
            entry_id: UUID of entry to delete
            hard: If True, permanently delete. If False, mark as deleted.

        Example:
            >>> vault.delete_entry(entry_id)  # Soft delete
            >>> vault.delete_entry(entry_id, hard=True)  # Permanent
        """
        self._require_unlocked()

        if hard:
            self.conn.execute("DELETE FROM entries WHERE id = ?", (entry_id,))
            self._audit("ENTRY_HARD_DELETE")
        else:
            self.conn.execute(
                "UPDATE entries SET deleted = 1 WHERE id = ?",
                (entry_id,)
            )
            self._audit("ENTRY_DELETE")

        self.conn.commit()

    def verify_audit_log(self) -> bool:
        """
        Verify audit log hasn't been tampered with.

        Returns:
            True if log is valid, False if tampered

        Example:
            >>> if vault.verify_audit_log():
            ...     print("Audit log is intact!")
            ... else:
            ...     print("WARNING: Audit log has been tampered with!")
        """
        self._require_unlocked()

        # Load all audit entries
        rows = self.conn.execute(
            "SELECT seq, action, prev_mac, mac FROM audit_log ORDER BY seq"
        ).fetchall()

        entries = [dict(row) for row in rows]

        return crypto.verify_audit_chain(self.audit_key, entries)

    # =========================================================================
    # INTERNAL HELPERS
    # =========================================================================

    def _derive_keys(self, master_password: str) -> None:
        """Derive all keys from master password."""
        # Derive vault key
        self.vault_key = crypto.derive_vault_key(master_password, self.salt)

        # Derive subkeys
        subkeys = crypto.derive_subkeys(self.vault_key)
        self.content_key = subkeys['content_key']
        self.audit_key = subkeys['audit_key']
        self.recovery_key = subkeys['recovery_key']

    def _audit(self, action: str) -> None:
        """Add entry to audit log."""
        # Get previous MAC
        prev_row = self.conn.execute(
            "SELECT mac FROM audit_log ORDER BY seq DESC LIMIT 1"
        ).fetchone()

        prev_mac = prev_row['mac'] if prev_row else None
        seq = (prev_row['seq'] + 1) if prev_row else 1

        # Compute new MAC
        mac = crypto.compute_audit_mac(self.audit_key, seq, action, prev_mac)

        # Store
        self.conn.execute(
            "INSERT INTO audit_log (timestamp, action, prev_mac, mac) VALUES (?, ?, ?, ?)",
            (int(time.time()), action, prev_mac, mac)
        )
        self.conn.commit()

    def _require_unlocked(self) -> None:
        """Check that vault is unlocked."""
        if not self.conn or not self.vault_key:
            raise Exception("Vault is locked. Call unlock() first.")


# =============================================================================
# EXAMPLE USAGE
# =============================================================================

if __name__ == "__main__":
    # Create and use a vault
    vault = Vault("test_vault.db")

    # Initialize with master password
    print("Creating new vault...")
    vault_id = vault.initialize("MyMasterPassword123!")
    print(f"Vault created: {vault_id}")

    # Add some entries
    print("\nAdding entries...")
    id1 = vault.add_entry(b"my_github_password")
    id2 = vault.add_entry(b"my_email_password")
    print(f"Added entries: {id1}, {id2}")

    # List entries
    print("\nEntries:")
    for entry in vault.list_entries():
        print(f"  {entry['id']}")

    # Retrieve
    print("\nRetrieving entry...")
    secret = vault.get_entry(id1)
    print(f"Secret: {secret}")

    # Verify audit log
    print("\nVerifying audit log...")
    if vault.verify_audit_log():
        print("✓ Audit log is intact!")
    else:
        print("✗ Audit log has been tampered!")

    # Lock vault
    vault.lock()
    print("\nVault locked.")
