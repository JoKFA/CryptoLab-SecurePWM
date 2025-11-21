"""
SecurePWM - Vault Module (Updated with username/site fields)
"""

import sqlite3
import os
import time
import uuid
import json
from typing import Optional, List, Dict
from . import crypto

SCHEMA = """
CREATE TABLE IF NOT EXISTS vault_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    vault_id TEXT NOT NULL,
    schema_version INTEGER NOT NULL DEFAULT 1,
    kdf TEXT NOT NULL,
    kdf_params TEXT NOT NULL,
    kdf_salt BLOB NOT NULL,
    aead_algo TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_unlock_at INTEGER
);

CREATE TABLE IF NOT EXISTS entries (
    id TEXT PRIMARY KEY,
    version INTEGER NOT NULL DEFAULT 1,
    username TEXT NOT NULL,
    site TEXT,
    username_hash BLOB NOT NULL,
    site_hash BLOB,
    key_nonce BLOB NOT NULL,
    key_wrapped BLOB NOT NULL,
    content_nonce BLOB NOT NULL,
    content_ciphertext BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    deleted INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_entries_username_hash ON entries(username_hash);
CREATE INDEX IF NOT EXISTS idx_entries_site_hash ON entries(site_hash);

CREATE TABLE IF NOT EXISTS audit_log (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    action TEXT NOT NULL,
    payload BLOB,
    prev_mac BLOB,
    mac BLOB NOT NULL
);
"""

PRAGMAS = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=FULL;
PRAGMA foreign_keys=ON;
PRAGMA secure_delete=ON;
"""

class Vault:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.conn: Optional[sqlite3.Connection] = None
        self.vault_id: Optional[str] = None
        self.salt: Optional[bytes] = None
        self.schema_version: int = 1
        self.kdf_params: Optional[dict] = None
        self.aead_algo: str = "aes256gcm"
        self.vault_key: Optional[bytes] = None
        self.content_key: Optional[bytes] = None
        self.audit_key: Optional[bytes] = None
        self.recovery_key: Optional[bytes] = None
        self.label_key: Optional[bytes] = None

    def initialize(self, master_password: str) -> str:
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(PRAGMAS)
        self.conn.executescript(SCHEMA)
        self.salt = os.urandom(16)
        self.vault_id = str(uuid.uuid4())
        self.schema_version = 1
        self.aead_algo = "aes256gcm"
        self.kdf_params = {"N": crypto.SCRYPT_N, "r": crypto.SCRYPT_R, "p": crypto.SCRYPT_P, "dkLen": 32}
        self.conn.execute(
            """INSERT INTO vault_state (id, vault_id, schema_version, kdf, kdf_params, kdf_salt, aead_algo, created_at)
               VALUES (1, ?, ?, ?, ?, ?, ?, ?)""",
            (self.vault_id, self.schema_version, "scrypt", json.dumps(self.kdf_params), self.salt, self.aead_algo, int(time.time()))
        )
        self.conn.commit()
        self._derive_keys(master_password)
        self._audit("VAULT_INIT")
        return self.vault_id

    def unlock(self, master_password: str) -> None:
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(PRAGMAS)
        row = self.conn.execute("SELECT * FROM vault_state WHERE id = 1").fetchone()
        if not row:
            raise Exception("Vault not initialized")
        self.vault_id = row['vault_id']
        self.salt = row['kdf_salt']
        self.schema_version = row['schema_version']
        self.aead_algo = row['aead_algo']
        self.kdf_params = json.loads(row['kdf_params'])
        self._derive_keys(master_password)
        self.conn.execute("UPDATE vault_state SET last_unlock_at = ? WHERE id = 1", (int(time.time()),))
        self.conn.commit()
        self._audit("VAULT_UNLOCK")

    def lock(self) -> None:
        self.vault_key = self.content_key = self.audit_key = self.recovery_key = self.label_key = None
        if self.conn:
            self.conn.close()
            self.conn = None

    def add_entry(self, secret: bytes, username: str, site: Optional[str] = None) -> str:
        """Add entry with required username and optional site."""
        self._require_unlocked()
        if not username or not username.strip():
            raise ValueError("Username is required")
        
        entry_id = str(uuid.uuid4())
        entry_key = crypto.create_entry_key()
        entry_version = 1
        now = int(time.time())
        
        username_hash = crypto.hash_label(self.label_key, username)
        site_hash = crypto.hash_label(self.label_key, site) if site else None
        
        content_nonce, content_ct = crypto.encrypt_entry_content(
            entry_key, secret, self.vault_id, entry_id, now, now, self.schema_version, entry_version
        )
        key_nonce, key_wrapped = crypto.wrap_entry_key(
            self.content_key, entry_key, self.vault_id, entry_id, self.schema_version, entry_version
        )
        
        self.conn.execute(
            """INSERT INTO entries (id, version, username, site, username_hash, site_hash,
               key_nonce, key_wrapped, content_nonce, content_ciphertext, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (entry_id, entry_version, username, site, username_hash, site_hash,
             key_nonce, key_wrapped, content_nonce, content_ct, now, now)
        )
        self.conn.commit()
        self._audit("ENTRY_ADD")
        return entry_id

    def get_entry(self, entry_id: str) -> Dict:
        """Get entry returning dict with secret, username, site."""
        self._require_unlocked()
        row = self.conn.execute(
            "SELECT * FROM entries WHERE id = ? AND deleted = 0", (entry_id,)
        ).fetchone()
        if not row:
            raise Exception(f"Entry {entry_id} not found")
        
        entry_key = crypto.unwrap_entry_key(
            self.content_key, row['key_nonce'], row['key_wrapped'],
            self.vault_id, entry_id, self.schema_version, row['version']
        )
        secret = crypto.decrypt_entry_content(
            entry_key, row['content_nonce'], row['content_ciphertext'],
            self.vault_id, entry_id, row['created_at'], row['updated_at'],
            self.schema_version, row['version']
        )
        self._audit("ENTRY_GET")
        return {
            'id': entry_id,
            'secret': secret,
            'username': row['username'],
            'site': row['site'],
            'created_at': row['created_at'],
            'updated_at': row['updated_at']
        }

    def list_entries(self) -> List[Dict]:
        """List entries with username and site visible."""
        self._require_unlocked()
        rows = self.conn.execute(
            "SELECT id, username, site, created_at, updated_at FROM entries WHERE deleted = 0"
        ).fetchall()
        return [dict(row) for row in rows]

    def search(self, query: str) -> List[Dict]:
        """
        Fuzzy search entries by username OR site.
        Searches both fields simultaneously using SQL LIKE.
        
        Note: This searches plaintext username/site columns.
        The hash columns are kept for exact-match lookups if needed.
        """
        self._require_unlocked()
        if not query or not query.strip():
            return self.list_entries()
        
        # Use % wildcards for fuzzy matching (case-insensitive via LOWER)
        pattern = f"%{query.lower()}%"
        rows = self.conn.execute(
            """SELECT id, username, site, created_at, updated_at 
               FROM entries 
               WHERE deleted = 0 
               AND (LOWER(username) LIKE ? OR LOWER(COALESCE(site, '')) LIKE ?)""",
            (pattern, pattern)
        ).fetchall()
        return [dict(row) for row in rows]

    def search_exact(self, username: str = None, site: str = None) -> List[Dict]:
        """Exact search using HMAC hashes (more secure, no fuzzy)."""
        self._require_unlocked()
        if username:
            h = crypto.hash_label(self.label_key, username)
            rows = self.conn.execute(
                "SELECT id, username, site, created_at, updated_at FROM entries WHERE username_hash = ? AND deleted = 0",
                (h,)
            ).fetchall()
        elif site:
            h = crypto.hash_label(self.label_key, site)
            rows = self.conn.execute(
                "SELECT id, username, site, created_at, updated_at FROM entries WHERE site_hash = ? AND deleted = 0",
                (h,)
            ).fetchall()
        else:
            return []
        return [dict(row) for row in rows]

    def delete_entry(self, entry_id: str, hard: bool = False) -> None:
        self._require_unlocked()
        if hard:
            self.conn.execute("DELETE FROM entries WHERE id = ?", (entry_id,))
            self._audit("ENTRY_HARD_DELETE")
        else:
            self.conn.execute("UPDATE entries SET deleted = 1 WHERE id = ?", (entry_id,))
            self._audit("ENTRY_DELETE")
        self.conn.commit()

    def verify_audit_log(self) -> bool:
        self._require_unlocked()
        rows = self.conn.execute(
            "SELECT seq, ts, action, payload, prev_mac, mac FROM audit_log ORDER BY seq"
        ).fetchall()
        return crypto.verify_audit_chain(self.audit_key, [dict(row) for row in rows])

    def _derive_keys(self, master_password: str) -> None:
        self.vault_key = crypto.derive_vault_key(master_password, self.salt)
        subkeys = crypto.derive_subkeys(self.vault_key)
        self.content_key = subkeys['content_key']
        self.audit_key = subkeys['audit_key']
        self.recovery_key = subkeys['recovery_key']
        self.label_key = subkeys['label_key']

    def _audit(self, action: str, payload: Optional[bytes] = None) -> None:
        prev_row = self.conn.execute("SELECT seq, mac FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
        prev_mac, seq = (prev_row['mac'], prev_row['seq'] + 1) if prev_row else (None, 1)
        ts = int(time.time())
        mac = crypto.compute_audit_mac(self.audit_key, seq, ts, action, prev_mac, payload)
        self.conn.execute("INSERT INTO audit_log (ts, action, payload, prev_mac, mac) VALUES (?, ?, ?, ?, ?)",
                          (ts, action, payload, prev_mac, mac))
        self.conn.commit()

    def _require_unlocked(self) -> None:
        if not self.conn or not self.vault_key:
            raise Exception("Vault is locked. Call unlock() first.")