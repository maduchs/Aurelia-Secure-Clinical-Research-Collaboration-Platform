# key_manager.py
# Advanced user key management for the clinical research platform.
#
# Responsibilities:
# 1. Derive a KEK from the user's password using Argon2id
# 2. Generate Ed25519 and X25519 keypairs
# 3. Encrypt private keys under the KEK before database storage
# 4. Support versioned keys so old data remains decryptable after rotation
# 5. Re-wrap all stored private keys when the user changes password

import os
import time
import json
import base64
from argon2.low_level import hash_secret_raw, Type

from crypto_core import (
    encrypt_data,
    decrypt_data,
    generate_ed25519_keypair,
    generate_x25519_keypair,
    serialise_public_key,
    serialise_private_key,
    deserialise_ed25519_private,
    deserialise_x25519_private,
    deserialise_public_key,
    public_key_fingerprint_from_pem
)
from storage import (
    get_connection,
    get_next_key_version,
    retire_active_keys,
    store_user_key_version,
    get_active_key_record,
    get_key_record,
    list_key_versions
)
from config import (
    ARGON2_TIME_COST,
    ARGON2_MEMORY_COST,
    ARGON2_PARALLELISM
)


def derive_kek(password: str, salt: bytes) -> bytes:
    """
    Derive a 256-bit Key Encryption Key from the user's password.

    Argon2id is used here because it is memory-hard and appropriate for
    password-based key derivation. The KEK is never stored directly.
    """
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=32,
        type=Type.ID
    )


def _build_key_bundle(password: str) -> dict:
    """
    Create one new logical key version for a user.

    Each version contains:
    - one Ed25519 pair for signing
    - one X25519 pair for key agreement
    - one KEK salt for deriving the wrapping key from the password

    The private keys are serialised to PEM and then encrypted with AES-GCM
    under the KEK. Public keys remain plaintext PEM so other users can use
    them for verification and secure sharing.
    """
    kek_salt = os.urandom(16)
    kek = derive_kek(password, kek_salt)

    ed_private, ed_public = generate_ed25519_keypair()
    x_private, x_public = generate_x25519_keypair()

    ed_private_pem = serialise_private_key(ed_private)
    x_private_pem = serialise_private_key(x_private)

    ed_private_enc = encrypt_data(kek, ed_private_pem)
    x_private_enc = encrypt_data(kek, x_private_pem)

    ed_public_pem = serialise_public_key(ed_public)
    x_public_pem = serialise_public_key(x_public)

    # Treat the two public keys as one logical identity version.
    combined_public_material = ed_public_pem + "\n" + x_public_pem
    key_fingerprint = public_key_fingerprint_from_pem(combined_public_material)

    return {
        "kek": kek,
        "kek_salt_b64": base64.b64encode(kek_salt).decode("utf-8"),
        "ed_private": ed_private,
        "ed_public": ed_public,
        "x_private": x_private,
        "x_public": x_public,
        "ed_private_enc": ed_private_enc,
        "x_private_enc": x_private_enc,
        "ed_public_pem": ed_public_pem,
        "x_public_pem": x_public_pem,
        "key_fingerprint": key_fingerprint
    }


def create_initial_keys(username: str, password: str) -> dict:
    """
    Create the first active key version for a new user.

    This should only happen once, immediately after registration.
    """
    key_version = get_next_key_version(username)
    if key_version != 1:
        raise ValueError("Initial key creation expected key version 1.")

    bundle = _build_key_bundle(password)
    created_at = time.time()

    store_user_key_version(
        username=username,
        key_version=key_version,
        status="active",
        x25519_private_enc=bundle["x_private_enc"],
        x25519_public=bundle["x_public_pem"],
        ed25519_private_enc=bundle["ed_private_enc"],
        ed25519_public=bundle["ed_public_pem"],
        key_fingerprint=bundle["key_fingerprint"],
        kek_salt=bundle["kek_salt_b64"],
        created_at=created_at,
        retired_at=None
    )

    bundle["username"] = username
    bundle["key_version"] = key_version
    bundle["status"] = "active"
    return bundle


def rotate_user_keys(username: str, password: str) -> dict:
    """
    Rotate a user's keys by retiring the current active version and creating
    a brand new active version.

    Old versions remain in the database so historical content can still be
    verified and decrypted when needed.
    """
    retired_at = time.time()
    retire_active_keys(username, retired_at)

    key_version = get_next_key_version(username)
    bundle = _build_key_bundle(password)
    created_at = time.time()

    store_user_key_version(
        username=username,
        key_version=key_version,
        status="active",
        x25519_private_enc=bundle["x_private_enc"],
        x25519_public=bundle["x_public_pem"],
        ed25519_private_enc=bundle["ed_private_enc"],
        ed25519_public=bundle["ed_public_pem"],
        key_fingerprint=bundle["key_fingerprint"],
        kek_salt=bundle["kek_salt_b64"],
        created_at=created_at,
        retired_at=None
    )

    bundle["username"] = username
    bundle["key_version"] = key_version
    bundle["status"] = "active"
    return bundle


def load_active_user_keys(username: str, password: str) -> dict:
    """
    Load the currently active key version for a user.

    This is the normal function used after login because new operations should
    use the active keys, not retired ones.
    """
    record = get_active_key_record(username)
    if not record:
        raise ValueError(f"No active key record found for '{username}'.")

    return load_user_keys_by_version(username, password, record["key_version"])


def load_user_keys_by_version(username: str, password: str, key_version: int) -> dict:
    """
    Load one specific key version for a user.

    This is useful when:
    - decrypting or verifying historical material
    - supporting key rotation
    - debugging version-specific issues
    """
    record = get_key_record(username, key_version)
    if not record:
        raise ValueError(f"No key version {key_version} found for '{username}'.")

    kek_salt = base64.b64decode(record["kek_salt"])
    kek = derive_kek(password, kek_salt)

    ed_private_pem = decrypt_data(kek, record["ed25519_private_enc"])
    x_private_pem = decrypt_data(kek, record["x25519_private_enc"])

    return {
        "username": username,
        "key_version": record["key_version"],
        "status": record["status"],
        "key_fingerprint": record["key_fingerprint"],
        "kek": kek,
        "ed_private": deserialise_ed25519_private(ed_private_pem),
        "ed_public": deserialise_public_key(record["ed25519_public"]),
        "x_private": deserialise_x25519_private(x_private_pem),
        "x_public": deserialise_public_key(record["x25519_public"]),
        "ed_public_pem": record["ed25519_public"],
        "x_public_pem": record["x25519_public"]
    }


def rewrap_all_user_private_keys(username: str, old_password: str, new_password: str) -> None:
    """
    Re-wrap every stored private key version under a new KEK.

    Important:
    This does not rotate the actual keypairs.
    It only changes the password-derived wrapping layer.

    - same public and private keys
    - same key versions
    - new KEK salt
    - new AES-GCM ciphertext for each stored private key
    """
    versions = list_key_versions(username)
    if not versions:
        raise ValueError(f"No key versions found for '{username}'.")

    conn = get_connection()

    try:
        for version in versions:
            record = get_key_record(username, version["key_version"])
            if not record:
                continue

            old_salt = base64.b64decode(record["kek_salt"])
            old_kek = derive_kek(old_password, old_salt)

            # First unwrap existing private keys using the old KEK.
            ed_private_pem = decrypt_data(old_kek, record["ed25519_private_enc"])
            x_private_pem = decrypt_data(old_kek, record["x25519_private_enc"])

            # Then derive a fresh KEK from the new password and a fresh salt.
            new_salt = os.urandom(16)
            new_kek = derive_kek(new_password, new_salt)

            new_ed_private_enc = encrypt_data(new_kek, ed_private_pem)
            new_x_private_enc = encrypt_data(new_kek, x_private_pem)

            conn.execute(
                """
                UPDATE user_key_versions
                SET ed25519_private_enc = ?,
                    x25519_private_enc = ?,
                    kek_salt = ?
                WHERE username = ? AND key_version = ?
                """,
                (
                    json.dumps(new_ed_private_enc),
                    json.dumps(new_x_private_enc),
                    base64.b64encode(new_salt).decode("utf-8"),
                    username,
                    record["key_version"]
                )
            )

        conn.commit()

    finally:
        conn.close()