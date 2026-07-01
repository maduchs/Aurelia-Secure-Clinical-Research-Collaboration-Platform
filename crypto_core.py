# crypto_core.py
# Core cryptographic operations.
# Uses AES-256-GCM, Ed25519, X25519, and HKDF-SHA256.

import os
import base64
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature


# ---------------------------------------------------------------------------
# AES-256-GCM helpers
# ---------------------------------------------------------------------------
# AES-256-GCM guarantees both confidentiality and integrity in a single authenticated pass
def encrypt_data(key: bytes, plaintext: bytes) -> dict:
    """Encrypt plaintext with AES-GCM and return a JSON-safe blob."""
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    return {
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode()
    }


def decrypt_data(key: bytes, blob: dict) -> bytes:
    """Decrypt an AES-GCM blob. Raises on tamper or wrong key."""
    nonce = base64.b64decode(blob["nonce"])
    ciphertext = base64.b64decode(blob["ciphertext"])
    return AESGCM(key).decrypt(nonce, ciphertext, None)


# ---------------------------------------------------------------------------
# Ed25519 signing
# ---------------------------------------------------------------------------

def generate_ed25519_keypair():
    """Generate an Ed25519 keypair for signatures."""
    private_key = Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()

# Uses Ed25519 over ECDSA to eliminate the risk of private key exposure through nonce reuse
def sign_data(private_key, data: bytes) -> str:
    """Sign data and return a base64 signature."""
    return base64.b64encode(private_key.sign(data)).decode()


def verify_signature(public_key, data: bytes, signature_b64: str) -> bool:
    """Verify an Ed25519 signature. Return True if valid."""
    try:
        public_key.verify(base64.b64decode(signature_b64), data)
        return True
    except (InvalidSignature, Exception):
        return False


# ---------------------------------------------------------------------------
# X25519 key agreement
# ---------------------------------------------------------------------------

def generate_x25519_keypair():
    """Generate an X25519 keypair for key agreement."""
    private_key = X25519PrivateKey.generate()
    return private_key, private_key.public_key()


def derive_shared_secret(private_key, peer_public_key) -> bytes:
    """Run X25519 Diffie-Hellman and return the shared secret."""
    return private_key.exchange(peer_public_key)


def derive_file_wrapping_key(shared_secret: bytes, salt: bytes) -> bytes:
    """Derive a 256-bit wrapping key from the shared secret using HKDF-SHA256."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"clinical-platform:file-wrapping-key",
        backend=default_backend()
    ).derive(shared_secret)


# ---------------------------------------------------------------------------
# Hybrid encryption for files
# ---------------------------------------------------------------------------
# Generates an ephemeral AES key for payload and wraps it using X25519 to provide Perfect Forward Secrecy
def encrypt_file(plaintext: bytes, recipient_x25519_public) -> dict:
    """
    Encrypt file content with a random AES key.
    Then wrap that AES key for the recipient using X25519 + HKDF + AES-GCM.
    """
    file_key = os.urandom(32)
    encrypted_content = encrypt_data(file_key, plaintext)

    ephemeral_private, ephemeral_public = generate_x25519_keypair()
    shared_secret = derive_shared_secret(ephemeral_private, recipient_x25519_public)

    salt = ephemeral_public.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw
    )
    wrapping_key = derive_file_wrapping_key(shared_secret, salt)
    wrapped_file_key = encrypt_data(wrapping_key, file_key)

    return {
        "ciphertext": encrypted_content["ciphertext"],
        "nonce": encrypted_content["nonce"],
        "wrapped_file_key": wrapped_file_key,
        "ephemeral_public": base64.b64encode(salt).decode()
    }


def decrypt_file(blob: dict, recipient_x25519_private) -> bytes:
    """Decrypt a hybrid-encrypted file blob."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

    ephemeral_pub_bytes = base64.b64decode(blob["ephemeral_public"])
    ephemeral_public = X25519PublicKey.from_public_bytes(ephemeral_pub_bytes)

    shared_secret = derive_shared_secret(recipient_x25519_private, ephemeral_public)
    wrapping_key = derive_file_wrapping_key(shared_secret, ephemeral_pub_bytes)

    wrapped = blob["wrapped_file_key"]
    if isinstance(wrapped, str):
        wrapped = json.loads(wrapped)

    file_key = decrypt_data(wrapping_key, wrapped)

    return AESGCM(file_key).decrypt(
        base64.b64decode(blob["nonce"]),
        base64.b64decode(blob["ciphertext"]),
        None
    )


def wrap_file_for_recipient(file_key: bytes, recipient_x25519_public) -> dict:
    """Wrap an existing file key for a new recipient without re-encrypting content."""
    ephemeral_private, ephemeral_public = generate_x25519_keypair()
    shared_secret = derive_shared_secret(ephemeral_private, recipient_x25519_public)

    salt = ephemeral_public.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw
    )
    wrapping_key = derive_file_wrapping_key(shared_secret, salt)
    wrapped = encrypt_data(wrapping_key, file_key)

    return {
        "wrapped_file_key": wrapped,
        "ephemeral_public": base64.b64encode(salt).decode()
    }


def unwrap_file_key(share_record: dict, recipient_x25519_private) -> bytes:
    """Unwrap a file key from a share record."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

    ephemeral_pub_bytes = base64.b64decode(share_record["ephemeral_public"])
    ephemeral_public = X25519PublicKey.from_public_bytes(ephemeral_pub_bytes)

    shared_secret = derive_shared_secret(recipient_x25519_private, ephemeral_public)
    wrapping_key = derive_file_wrapping_key(shared_secret, ephemeral_pub_bytes)

    wrapped = share_record["wrapped_file_key"]
    if isinstance(wrapped, str):
        wrapped = json.loads(wrapped)

    return decrypt_data(wrapping_key, wrapped)


# ---------------------------------------------------------------------------
# Key serialisation helpers
# ---------------------------------------------------------------------------

def serialise_public_key(public_key) -> str:
    """Convert a public key object to PEM text."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()


def deserialise_public_key(pem_str: str):
    """Load a PEM public key string back into an object."""
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    return load_pem_public_key(pem_str.encode(), backend=default_backend())


def serialise_private_key(private_key) -> bytes:
    """Convert a private key object to PKCS8 PEM bytes."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )


def deserialise_ed25519_private(pem_bytes: bytes):
    """Load an Ed25519 private key from PEM bytes."""
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    return load_pem_private_key(pem_bytes, password=None, backend=default_backend())


def deserialise_x25519_private(pem_bytes: bytes):
    """Load an X25519 private key from PEM bytes."""
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    return load_pem_private_key(pem_bytes, password=None, backend=default_backend())


def public_key_fingerprint_from_pem(pem_text: str) -> str:
    """Return a stable SHA-256 fingerprint of PEM text as base64."""
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(pem_text.encode("utf-8"))
    return base64.b64encode(digest.finalize()).decode("utf-8")