# Aurelia -- Secure Clinical Research Collaboration Platform

A Python cryptosystem for secure cross-border sharing of sensitive medical data between healthcare institutions, research teams, and auditors. Demonstrates applied cryptography including authenticated encryption, digital signatures, hierarchical key management, and tamper-evident audit logging.

---

## Features

- AES-256-GCM authenticated encryption for all stored data
- Ed25519 digital signatures; auditors verify integrity without decryption access
- X25519 ephemeral key agreement with per-recipient file key wrapping
- Argon2id password hashing and Key Encryption Key (KEK) derivation
- HMAC-SHA256 chained audit log with tamper detection
- TOTP-based multi-factor authentication
- Role-based access control with cryptographic enforcement
- GDPR-aligned: consent basis field, right to erasure, data minimisation in logs

---

## Cryptographic Design

```
Password --> Argon2id --> KEK
                          |
              AES-GCM encrypts Ed25519 + X25519 private keys

File upload:
  Plaintext --> SHA-256 hash --> Ed25519 signature
            --> AES-256-GCM encrypt (random file key)
            --> X25519 ECDH + HKDF --> wrap file key per recipient
```

Password changes re-wrap all private keys under a new KEK without rotating keypairs. Key rotation retires the active keypair while preserving historical verifiability.

---

## Roles

| Role | Capabilities |
|------|-------------|
| Researcher | Upload and sign findings, view, share with other researchers |
| Clinician | Upload patient datasets with consent basis, share with other clinicians, erase |
| Auditor | Verify signatures, verify HMAC audit chain -- no decryption access |
| Administrator | Manage users, export system backup |

---

## Setup

Python 3.10+ required.

```bash
git clone https://github.com/yourusername/aurelia.git
cd aurelia
pip install -r requirements.txt
python main.py
```

On first run you will be prompted to create the admin account. The SQLite database is initialised automatically.

---

## File Structure

```
main.py           Entry point, role menus, session management
auth.py           Registration, Argon2id hashing, TOTP, account lockout
crypto_core.py    AES-GCM, Ed25519, X25519, HKDF primitives
key_manager.py    KEK derivation, key versioning, rotation, rewrapping
audit_log.py      HMAC-chained audit log and integrity verification
storage.py        SQLite persistence layer
config.py         System constants (Argon2 parameters, session timeout, lockout)
requirements.txt  Dependencies
```

---

## .gitignore

Add this to your repo root:

```
*.db
*.sqlite
*.sqlite3
audit_hmac.key
backups/
__pycache__/
*.pyc
```

---

## Note

This is a prototype for demonstration purposes. Production deployment would require secure TOTP provisioning, policy-enforced key rotation, dual-admin approval for sensitive actions, and PKI infrastructure for organisational identity assurance.
