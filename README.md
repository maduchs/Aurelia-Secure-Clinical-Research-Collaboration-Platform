# Aurelia-Secure-Clinical-Research-Collaboration-Platform
A Python-based cryptosystem for secure cross-border sharing of sensitive medical data between healthcare institutions, research teams, and auditors. Built as a demonstration of applied cryptography principles including authenticated encryption, digital signatures, key derivation, and tamper-evident audit logging.

---

## What it does

Aurelia implements a multi-role secure file-sharing platform with the following properties:

- **Confidentiality** : AES-256-GCM authenticated encryption for all stored data
- **Integrity** : SHA-256 content hashing with Ed25519 digital signatures, verified independently of decryption
- **Authenticity** : Per-user Ed25519 signing keypairs; auditors can verify signatures without accessing plaintext
- **Access control** : Role-based menus (Researcher, Clinician, Auditor, Administrator) with cryptographic enforcement
- **Key management** : X25519 ephemeral key agreement with per-user KEK wrapping via Argon2id
- **Audit trail** : HMAC-SHA256 chained audit log; tampering is detectable at the specific broken entry
- **MFA** : TOTP-based two-factor authentication via pyotp
- **GDPR alignment** : Consent basis field, right-to-erasure implementation, data minimisation in audit logs

---

## Cryptographic architecture

Each user has an independent cryptographic identity:

```
Password → Argon2id → KEK
                        ↓
              AES-GCM encrypts Ed25519 + X25519 private keys
              (stored in DB; never in plaintext)

File upload:
  Plaintext → SHA-256 hash → Ed25519 sign
           → AES-256-GCM encrypt (random file key)
           → X25519 ECDH + HKDF → wrap file key per recipient
```

Key rotation retires the active keypair without re-encrypting historical files. Password changes re-wrap all private keys under a new KEK without rotating the underlying keypairs, preserving historical verifiability.

---

## Roles

| Role | Capabilities |
|------|-------------|
| Researcher | Upload and sign findings, view, share with other researchers |
| Clinician | Upload patient datasets with consent basis, share with other clinicians, erase |
| Auditor | Verify signatures, view and verify HMAC audit log chain, no decryption access |
| Administrator | Manage users, export system backup, rotate keys |

Role-scoped sharing is cryptographically enforced - sharing across role boundaries is rejected at the key-wrapping layer.

---

## Setup

**Requirements:** Python 3.10+

```bash
git clone https://github.com/yourusername/aurelia.git
cd aurelia
pip install -r requirements.txt
python main.py
```

On first run, you will be prompted to create the built-in admin account. The system bootstraps the SQLite database automatically.

**requirements.txt:**
```
cryptography
argon2-cffi
pyotp
```

---

## Test accounts

After running setup, register accounts via the main menu or use the admin panel to create users. One account per role is needed to explore all functionality. Example credentials used during development (do not use in any real deployment):

| Username | Role | Password |
|----------|------|----------|
| lily_mathew | Researcher | Waterlily@10 |
| jakethomas | Clinician | Applepie*19 |
| claral | Auditor | Mocha67$ |

Password requirements: minimum 8 characters, uppercase, lowercase, digit, special character.

---

## Security notes

This is a **prototype** for demonstration purposes. The following would be required before any production deployment:

- TOTP secrets provisioned via secure out-of-band channel (not displayed on screen)
- Key rotation enforced by administrative policy at defined cryptoperiods
- Dual-admin approval for sensitive administrative actions
- Certificate infrastructure (PKI/X.509) for organisational identity assurance
- Granular dataset-level backup and recovery
- HSM or secure enclave for KEK storage

---

## File structure

```
main.py          # Entry point, role menus, session management
auth.py          # Registration, Argon2id hashing, TOTP, account lockout
crypto_core.py   # AES-GCM, Ed25519, X25519, HKDF — all cryptographic primitives
key_manager.py   # KEK derivation, key bundle creation, versioning, rotation, rewrapping
audit_log.py     # HMAC-SHA256 chained audit log, sanitisation, integrity verification
storage.py       # SQLite persistence layer
config.py        # System constants (session timeout, Argon2 parameters, lockout config)
```

---

