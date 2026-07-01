# storage.py
# SQLite operations for all persistent state.

import sqlite3
import json
import time
from config import DB_FILE


def get_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

# Sets up SQLite schema with foreign keys for relational integrity for users, keys, files, and shares
def initialise_db():
    conn = get_connection()
    c = conn.cursor()

    c.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL,
        first_name TEXT,
        last_name TEXT,
        location TEXT,
        totp_secret TEXT NOT NULL,
        failed_attempts INTEGER DEFAULT 0,
        locked_until REAL DEFAULT 0,
        account_status TEXT DEFAULT 'active',
        password_changed_at REAL,
        mfa_reset_at REAL,
        created_at REAL NOT NULL
    );

    CREATE TABLE IF NOT EXISTS user_key_versions (
        username TEXT NOT NULL,
        key_version INTEGER NOT NULL,
        status TEXT NOT NULL,
        x25519_private_enc TEXT NOT NULL,
        x25519_public TEXT NOT NULL,
        ed25519_private_enc TEXT NOT NULL,
        ed25519_public TEXT NOT NULL,
        key_fingerprint TEXT NOT NULL,
        kek_salt TEXT NOT NULL,
        created_at REAL NOT NULL,
        retired_at REAL,
        PRIMARY KEY (username, key_version),
        FOREIGN KEY (username) REFERENCES users(username)
    );

    CREATE TABLE IF NOT EXISTS files (
        file_id TEXT PRIMARY KEY,
        owner TEXT NOT NULL,
        role TEXT NOT NULL,
        filename TEXT NOT NULL,
        ciphertext TEXT NOT NULL,
        nonce TEXT NOT NULL,
        signature TEXT NOT NULL,
        content_hash TEXT NOT NULL DEFAULT '',
        ed25519_public TEXT NOT NULL,
        created_at REAL NOT NULL,
        FOREIGN KEY (owner) REFERENCES users(username)
    );

    CREATE TABLE IF NOT EXISTS shares (
        share_id TEXT PRIMARY KEY,
        file_id TEXT NOT NULL,
        shared_by TEXT NOT NULL,
        shared_with TEXT NOT NULL,
        wrapped_file_key TEXT NOT NULL,
        ephemeral_public TEXT NOT NULL,
        created_at REAL NOT NULL,
        FOREIGN KEY (file_id) REFERENCES files(file_id)
    );

    CREATE TABLE IF NOT EXISTS audit_log (
        entry_id INTEGER PRIMARY KEY AUTOINCREMENT,
        data TEXT NOT NULL,
        hmac TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_user_key_versions_user
    ON user_key_versions(username);

    CREATE INDEX IF NOT EXISTS idx_user_key_versions_status
    ON user_key_versions(username, status);

    CREATE INDEX IF NOT EXISTS idx_files_owner
    ON files(owner);

    CREATE INDEX IF NOT EXISTS idx_files_role
    ON files(role);

    CREATE INDEX IF NOT EXISTS idx_shares_shared_with
    ON shares(shared_with);

    CREATE INDEX IF NOT EXISTS idx_shares_shared_by
    ON shares(shared_by);

    CREATE INDEX IF NOT EXISTS idx_shares_file_id
    ON shares(file_id);
    """)

    existing_cols = [row["name"] for row in c.execute("PRAGMA table_info(users)").fetchall()]
    migrations = {
        "first_name": "ALTER TABLE users ADD COLUMN first_name TEXT",
        "last_name": "ALTER TABLE users ADD COLUMN last_name TEXT",
        "location": "ALTER TABLE users ADD COLUMN location TEXT",
        "account_status": "ALTER TABLE users ADD COLUMN account_status TEXT DEFAULT 'active'",
        "password_changed_at": "ALTER TABLE users ADD COLUMN password_changed_at REAL",
        "mfa_reset_at": "ALTER TABLE users ADD COLUMN mfa_reset_at REAL",
    }
    for col, stmt in migrations.items():
        if col not in existing_cols:
            c.execute(stmt)

    file_cols = [row["name"] for row in c.execute("PRAGMA table_info(files)").fetchall()]
    file_migrations = {
        "content_hash": "ALTER TABLE files ADD COLUMN content_hash TEXT NOT NULL DEFAULT ''",
    }
    for col, stmt in file_migrations.items():
        if col not in file_cols:
            c.execute(stmt)

    conn.commit()
    conn.close()


def create_user(username, password_hash, role, totp_secret, created_at, first_name=None, last_name=None, location=None):
    conn = get_connection()
    conn.execute(
        """
        INSERT INTO users (
            username, password_hash, role, first_name, last_name, location,
            totp_secret, failed_attempts, locked_until, account_status,
            password_changed_at, mfa_reset_at, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0, 'active', ?, NULL, ?)
        """,
        (
            username,
            password_hash,
            role,
            first_name,
            last_name,
            location,
            totp_secret,
            created_at,
            created_at,
        )
    )
    conn.commit()
    conn.close()


def get_user(username):
    conn = get_connection()
    row = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    conn.close()
    return dict(row) if row else None


def update_failed_attempts(username, attempts, locked_until=0):
    conn = get_connection()
    conn.execute(
        "UPDATE users SET failed_attempts=?, locked_until=? WHERE username=?",
        (attempts, locked_until, username)
    )
    conn.commit()
    conn.close()


def reset_failed_attempts(username):
    conn = get_connection()
    conn.execute(
        "UPDATE users SET failed_attempts=0, locked_until=0 WHERE username=?",
        (username,)
    )
    conn.commit()
    conn.close()


def update_password_hash(username, password_hash):
    conn = get_connection()
    conn.execute(
        "UPDATE users SET password_hash=?, password_changed_at=? WHERE username=?",
        (password_hash, time.time(), username)
    )
    conn.commit()
    conn.close()

# Persists key versions. Private keys are AES-GCM encrypted; public keys are plaintext
def store_user_key_version(
    username,
    key_version,
    status,
    x25519_private_enc,
    x25519_public,
    ed25519_private_enc,
    ed25519_public,
    key_fingerprint,
    kek_salt,
    created_at,
    retired_at=None,
):
    conn = get_connection()
    conn.execute(
        """
        INSERT INTO user_key_versions (
            username, key_version, status, x25519_private_enc, x25519_public,
            ed25519_private_enc, ed25519_public, key_fingerprint,
            kek_salt, created_at, retired_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            username,
            key_version,
            status,
            json.dumps(x25519_private_enc),
            x25519_public,
            json.dumps(ed25519_private_enc),
            ed25519_public,
            key_fingerprint,
            kek_salt,
            created_at,
            retired_at,
        )
    )
    conn.commit()
    conn.close()


def get_next_key_version(username):
    conn = get_connection()
    row = conn.execute(
        """
        SELECT COALESCE(MAX(key_version), 0) AS max_version
        FROM user_key_versions
        WHERE username=?
        """,
        (username,)
    ).fetchone()
    conn.close()
    return int(row["max_version"]) + 1


def retire_active_keys(username, retired_at):
    conn = get_connection()
    conn.execute(
        """
        UPDATE user_key_versions
        SET status='retired', retired_at=?
        WHERE username=? AND status='active'
        """,
        (retired_at, username)
    )
    conn.commit()
    conn.close()

# Fetches the most recent, non-retired key bundle for operations
def get_active_key_record(username):
    conn = get_connection()
    row = conn.execute(
        """
        SELECT *
        FROM user_key_versions
        WHERE username=? AND status='active'
        ORDER BY key_version DESC
        LIMIT 1
        """,
        (username,)
    ).fetchone()
    conn.close()

    if not row:
        return None

    record = dict(row)
    record["x25519_private_enc"] = json.loads(record["x25519_private_enc"])
    record["ed25519_private_enc"] = json.loads(record["ed25519_private_enc"])
    return record


def get_key_record(username, key_version):
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM user_key_versions WHERE username=? AND key_version=?",
        (username, key_version)
    ).fetchone()
    conn.close()

    if not row:
        return None

    record = dict(row)
    record["x25519_private_enc"] = json.loads(record["x25519_private_enc"])
    record["ed25519_private_enc"] = json.loads(record["ed25519_private_enc"])
    return record


def list_key_versions(username):
    conn = get_connection()
    rows = conn.execute(
        """
        SELECT username, key_version, status, key_fingerprint, created_at, retired_at
        FROM user_key_versions
        WHERE username=?
        ORDER BY key_version DESC
        """,
        (username,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_user_active_public_keys(username):
    conn = get_connection()
    row = conn.execute(
        """
        SELECT username, key_version, x25519_public, ed25519_public, key_fingerprint, status
        FROM user_key_versions
        WHERE username=? AND status='active'
        ORDER BY key_version DESC
        LIMIT 1
        """,
        (username,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def store_file(file_id, owner, role, filename, ciphertext, nonce, signature, content_hash, ed25519_public, created_at):
    conn = get_connection()
    conn.execute(
        """
        INSERT INTO files (
            file_id, owner, role, filename, ciphertext,
            nonce, signature, content_hash, ed25519_public, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            file_id,
            owner,
            role,
            filename,
            ciphertext,
            nonce,
            signature,
            content_hash,
            ed25519_public,
            created_at,
        )
    )
    conn.commit()
    conn.close()


def get_files_for_role(role):
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM files WHERE role=? ORDER BY created_at DESC",
        (role,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_file(file_id):
    conn = get_connection()
    row = conn.execute("SELECT * FROM files WHERE file_id=?", (file_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def delete_file(file_id):
    conn = get_connection()
    conn.execute("DELETE FROM shares WHERE file_id=?", (file_id,))
    conn.execute("DELETE FROM files WHERE file_id=?", (file_id,))
    conn.commit()
    conn.close()


def store_share(share_id, file_id, shared_by, shared_with, wrapped_file_key, ephemeral_public, created_at):
    conn = get_connection()
    conn.execute(
        """
        INSERT INTO shares (
            share_id, file_id, shared_by, shared_with,
            wrapped_file_key, ephemeral_public, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            share_id,
            file_id,
            shared_by,
            shared_with,
            json.dumps(wrapped_file_key),
            ephemeral_public,
            created_at,
        )
    )
    conn.commit()
    conn.close()


def get_shares_for_user(username):
    conn = get_connection()
    rows = conn.execute(
        """
        SELECT
            s.*, f.filename, f.ciphertext, f.nonce, f.signature,
            f.content_hash, f.ed25519_public, f.owner, f.role
        FROM shares s
        JOIN files f ON s.file_id = f.file_id
        WHERE s.shared_with=?
        ORDER BY s.created_at DESC
        """,
        (username,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_shares_by_user(username):
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM shares WHERE shared_by=? ORDER BY created_at DESC",
        (username,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def append_audit_entry(data: str, hmac_value: str):
    conn = get_connection()
    conn.execute("INSERT INTO audit_log (data, hmac) VALUES (?, ?)", (data, hmac_value))
    conn.commit()
    conn.close()


def get_all_audit_entries():
    conn = get_connection()
    rows = conn.execute("SELECT data, hmac FROM audit_log ORDER BY entry_id").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_last_audit_hmac():
    conn = get_connection()
    row = conn.execute("SELECT hmac FROM audit_log ORDER BY entry_id DESC LIMIT 1").fetchone()
    conn.close()
    return row["hmac"] if row else "0" * 64

def update_user_status(username, status):
    conn = get_connection()
    conn.execute(
        "UPDATE users SET account_status=? WHERE username=?",
        (status, username)
    )
    conn.commit()
    conn.close()

def list_users():
    conn = get_connection()
    rows = conn.execute(
        """
        SELECT username, role, first_name, last_name, location,
               account_status, created_at, password_changed_at
        FROM users
        ORDER BY created_at ASC
        """
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]