# audit_log.py
# HMAC-SHA256 chained audit logging.

import os
import json
import hmac
import time
import hashlib

from storage import append_audit_entry, get_all_audit_entries, get_last_audit_hmac

HMAC_KEY_FILE = "audit_hmac.key"
GENESIS_PREV = "0" * 64


def _load_hmac_key() -> bytes:
    if os.path.exists(HMAC_KEY_FILE):
        if os.name != "nt":
            mode = os.stat(HMAC_KEY_FILE).st_mode & 0o777
            if mode & 0o077:
                raise PermissionError(
                    "audit_hmac.key permissions are too broad; expected owner-only access."
                )
        with open(HMAC_KEY_FILE, "rb") as f:
            return f.read()

    key = os.urandom(32)
    fd = os.open(HMAC_KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key)
    return key

# Cryptographically binds the current entry to the previous HMAC for immutability
def _compute_hmac(key: bytes, prev_hmac: str, entry_json: str) -> str:
    msg = (prev_hmac + entry_json).encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()

# Strips PII before logging to meet GDPR Data Minimisation rules
def sanitise_audit_detail(action: str, detail: str) -> str:
    if not detail:
        return ""

    allowed_prefixes = {
        "USER_REGISTERED": {"user=", "role="},
        "LOGIN_SUCCESS": {"MFA"},
        "LOGIN_BLOCKED": {"locked_for="},
        "UPLOAD_FINDING": {"file_id="},
        "VIEW_FINDING": {"file_id="},
        "VIEW_SHARED_FINDING": {"file_id="},
        "SHARE_FINDING": {"file_id=", "with="},
        "UPLOAD_DATASET": {"file_id=", "subject_ref="},
        "VIEW_DATASET": {"file_id="},
        "VIEW_SHARED_DATASET": {"file_id="},
        "SHARE_DATASET": {"file_id=", "with="},
        "ERASE_DATASET": {"file_id="},
        "DECRYPT_FAIL": {"file_id=", "error="},
        "UNWRAP_FAIL": {"file_id=", "error="},
        "RESHARE_DENIED": {"file_id="},
        "VERIFY_LOG_INTEGRITY": {"valid="},
        "VERIFY_SIGNATURE": {"file_id=", "valid="},
        "VIEW_AUDIT_LOG": {"entries"},
    }

    prefixes = allowed_prefixes.get(action)
    if prefixes is None:
        return ""

    tokens = detail.split()
    safe_tokens = []

    for token in tokens:
        if token == "MFA" and "MFA" in prefixes:
            safe_tokens.append(token)
            continue
        if token == "verified" and "MFA" in prefixes:
            safe_tokens.append(token)
            continue
        if token == "entries" and "entries" in prefixes:
            safe_tokens.append(token)
            continue

        for prefix in prefixes:
            if token.startswith(prefix):
                safe_tokens.append(token)
                break

    return " ".join(safe_tokens)


def log_event(user: str, role: str, action: str, detail: str = "") -> None:
    key = _load_hmac_key()
    prev_hmac = get_last_audit_hmac() or GENESIS_PREV
    safe_detail = sanitise_audit_detail(action, detail)

    entry_data = json.dumps({
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "user": user,
        "role": role,
        "action": action,
        "detail": safe_detail
    }, separators=(",", ":"))
# Cryptographically binds the new event to the previous digest to ensure tamper-evidence
    entry_hmac = _compute_hmac(key, prev_hmac, entry_data)
    append_audit_entry(entry_data, entry_hmac)

# Recalculates the HMAC chain to detect tampering or deletions
def verify_log_integrity() -> tuple:
    key = _load_hmac_key()
    entries = get_all_audit_entries()

    tampered = []
    prev_digest = GENESIS_PREV

    for i, entry in enumerate(entries):
        expected = _compute_hmac(key, prev_digest, entry["data"])
        if not hmac.compare_digest(expected, entry["hmac"]):
            tampered.append(i)
        prev_digest = entry["hmac"]

    return (len(tampered) == 0, tampered)


def read_log() -> list:
    return [json.loads(e["data"]) for e in get_all_audit_entries()]