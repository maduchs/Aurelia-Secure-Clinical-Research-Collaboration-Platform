# main.py
# Entry point, registration, login, MFA, and session management.
import os
import shutil
import time
import getpass
import uuid
import json
import pyotp
import hashlib
from cryptography.exceptions import InvalidTag
from datetime import datetime
from config import SESSION_TIMEOUT_SECONDS, TOTP_ISSUER
from storage import (
    initialise_db,
    get_user,
    get_files_for_role,
    get_file,
    delete_file,
    store_file,
    store_share,
    get_shares_for_user,
    get_user_active_public_keys,
    list_users,
    update_user_status,
)
from auth import authenticate, register_user, verify_totp, change_password
from audit_log import log_event, verify_log_integrity, read_log
from key_manager import load_active_user_keys, rotate_user_keys
from crypto_core import (
    encrypt_file,
    decrypt_file,
    wrap_file_for_recipient,
    unwrap_file_key,
    sign_data,
    verify_signature,
    serialise_public_key,
    deserialise_public_key,
)

PLATFORM_NAME = "Aurelia Clinical Research Platform"
PLATFORM_TAGLINE = "Cross-Border Clinical Research Collaboration"
OTP_DISPLAY_SECONDS = 90

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


def colour(text: str, code: str) -> str:
    return f"{code}{text}{RESET}"

# Limits active session windows to mitigate the risk of session hijacking
def check_session(session_start: float) -> bool:
    return (time.time() - session_start) < SESSION_TIMEOUT_SECONDS


def display_current_otp(user: dict, username: str) -> None:
    current_otp = pyotp.TOTP(user["totp_secret"]).now()
    print(colour(f"[DEMO] Current MFA code for {username}: {current_otp}", YELLOW))

def export_backup(username: str, role: str) -> None:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_root = "backups"
    os.makedirs(backup_root, exist_ok=True)

    export_dir = os.path.join(backup_root, f"{username}_{timestamp}")
    os.makedirs(export_dir, exist_ok=True)

    copied_any = False

    for folder in ["keys", "data", "logs"]:
        if os.path.isdir(folder):
            shutil.copytree(folder, os.path.join(export_dir, folder), dirs_exist_ok=True)
            copied_any = True

    for filename in os.listdir("."):
        if filename.endswith(".db") or filename.endswith(".sqlite") or filename.endswith(".sqlite3"):
            shutil.copy2(filename, os.path.join(export_dir, filename))
            copied_any = True

    archive_base = os.path.join(backup_root, f"{username}_{timestamp}")
    archive_path = shutil.make_archive(archive_base, "zip", export_dir)

    if copied_any:
        log_event(username, role, "BACKUP_EXPORT", f"path={archive_path}")
        print(colour(f"[OK] Backup created: {archive_path}", GREEN))
    else:
        print(colour("[!] No backup source files were found.", RED))

def self_key_rotation_flow(username: str, role: str, password: str) -> bool:
    print("\n--- Rotate My Cryptographic Keys ---")
    print("This will create a new active signing and encryption key version.")
    print("Previous key versions will remain stored for historical verification.")
    confirm = input("Type ROTATE to continue: ").strip()

    if confirm != "ROTATE":
        print(colour("[!] Key rotation cancelled.", YELLOW))
        return False

    try:
        new_keys = rotate_user_keys(username, password)
        log_event(
            username,
            role,
            "KEY_ROTATED",
            f"self new_version={new_keys['key_version']} fingerprint={new_keys['key_fingerprint']}"
        )
        print(colour(
            f"[OK] Keys rotated successfully. New active version: {new_keys['key_version']}",
            GREEN
        ))
        print(colour("[!] Please log in again to continue with the new active keys.", YELLOW))
        return True
    except Exception as e:
        print(colour(f"[!] Key rotation failed: {e}", RED))
        log_event(username, role, "KEY_ROTATION_FAIL", f"self error={type(e).__name__}")
        return False

def format_timestamp(ts):
    if not ts:
        return "Never"
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")

def password_change_flow(username: str, role: str) -> bool:
    print("\n--- Change Password ---")
    current_password = getpass.getpass("Current password: ")
    new_password = getpass.getpass("New password: ")
    confirm_password = getpass.getpass("Confirm new password: ")

    if new_password != confirm_password:
        print(colour("! New passwords do not match.", RED))
        log_event(username, role, "PASSWORD_CHANGE_FAIL", "confirmation_mismatch")
        return False

    if current_password == new_password:
        print(colour("! New password must be different from the current password.", RED))
        log_event(username, role, "PASSWORD_CHANGE_FAIL", "password_reuse")
        return False

    try:
        change_password(username, current_password, new_password)
        print(colour("OK Password changed successfully. Please log in again.", GREEN))
        log_event(username, role, "PASSWORD_CHANGED", "")
        return True
    except Exception as e:
        print(colour(f"! Password change failed: {e}", RED))
        log_event(username, role, "PASSWORD_CHANGE_FAIL", type(e).__name__)
        return False
    
def user_creation_flow(created_by=None, creator_role=None, admin_mode=False):
    print("\n--- Create New User ---" if admin_mode else "\n--- Register New Account ---")

    first_name = input("First name         : ").strip()
    last_name = input("Last name          : ").strip()
    location = input("Location           : ").strip()
    new_username = input("Username           : ").strip()

    print("Select role:")
    print("  1  Researcher")
    print("  2  Clinician")
    print("  3  Auditor")
    role_map = {"1": "researcher", "2": "clinician", "3": "auditor"}
    role_choice = input("Role: ").strip()
    new_role = role_map.get(role_choice)

    if not new_role:
        print(colour("[!] Invalid role.", RED))
        return

    if get_user(new_username):
        print(colour("[!] Username already exists.", RED))
        return

    print(colour(
        "Password requirements: at least 8 characters, one uppercase letter, one lowercase letter, one digit, and one special character.",
        YELLOW
    ))

    new_password = getpass.getpass("Temporary password : " if admin_mode else "Password           : ")
    confirm_password = getpass.getpass("Confirm password   : ")

    if new_password != confirm_password:
        print(colour("[!] Passwords do not match.", RED))
        return

    try:
        totp_secret = register_user(
            username=new_username,
            password=new_password,
            role=new_role,
            first_name=first_name,
            last_name=last_name,
            location=location,
        )

        uri = pyotp.TOTP(totp_secret).provisioning_uri(
            name=new_username,
            issuer_name=TOTP_ISSUER,
        )

        print(colour(f"[OK] User created: {new_username} ({new_role})", GREEN))
        print(colour(f"[!] TOTP Secret: {totp_secret}", YELLOW))
        print(colour("[!] Add to authenticator app:", YELLOW))
        print(f"    {uri}")

        if admin_mode:
            log_event(
                created_by,
                creator_role,
                "ADMIN_CREATE_USER",
                f"user={new_username} role={new_role}"
            )
        else:
            log_event(
                "SYSTEM",
                "admin",
                "USER_REGISTERED",
                f"user={new_username} role={new_role}"
            )

    except ValueError as e:
        print(colour(f"[!] {e}", RED))
# Enforces RBAC and validates session timeouts per loop iteration
def researcher_menu(username: str, keys: dict, session_start: float, password: str) -> None:
    role = "researcher"

    while True:
        if not check_session(session_start):
            print(colour("[!] Session expired. Please log in again.", RED))
            log_event(username, role, "SESSION_TIMEOUT", "")
            break

        print("\n--- Researcher Menu ---")
        print("1 Upload and sign a finding")
        print("2 View my findings")
        print("3 View findings shared with me")
        print("4 Share a finding with another researcher")
        print("5 Change password")
        print("6 Rotate my cryptographic keys")
        print("7 Logout")
        choice = input("Choice: ").strip()
# Hash content, sign with Ed25519, and hybrid-encrypt the payload
        if choice == "1":
            filename = input("Finding name : ").strip()
            content = input("Finding text : ").encode("utf-8")
            content_hash = hashlib.sha256(content).hexdigest()

            signature = sign_data(keys["ed_private"], content_hash.encode("utf-8"))
            blob = encrypt_file(content, keys["x_public"])

            file_id = str(uuid.uuid4())
            store_file(
                file_id=file_id,
                owner=username,
                role=role,
                filename=filename,
                ciphertext=blob["ciphertext"],
                nonce=blob["nonce"],
                signature=signature,
                content_hash=content_hash,
                ed25519_public=serialise_public_key(keys["ed_public"]),
                created_at=time.time(),
            )

            store_share(
                share_id=str(uuid.uuid4()),
                file_id=file_id,
                shared_by=username,
                shared_with=username,
                wrapped_file_key=blob["wrapped_file_key"],
                ephemeral_public=blob["ephemeral_public"],
                created_at=time.time(),
            )

            log_event(username, role, "UPLOAD_FINDING", f"file_id={file_id}")
            print(colour(f"[OK] Finding uploaded and signed. ID: {file_id}", GREEN))

        elif choice == "2":
            shares = get_shares_for_user(username)
            my_shares = [
                s for s in shares
                if s["shared_by"] == username and s["shared_with"] == username
            ]

            if not my_shares:
                print("No findings on record.")
                continue

            for i, s in enumerate(my_shares):
                print(f"  [{i}] {s['filename']} (ID: {s['file_id']})")

            try:
                idx = int(input("Select: "))
                if not (0 <= idx < len(my_shares)):
                    print(colour("[!] Invalid selection.", RED))
                    continue
            except ValueError:
                print(colour("[!] Enter a number.", RED))
                continue

            share = my_shares[idx]
            file_rec = get_file(share["file_id"])

            if not file_rec:
                print(colour("[!] File record missing.", RED))
                log_event(username, role, "VIEW_FAIL", f"file_missing={share['file_id']}")
                continue

            try:
                plaintext = decrypt_file(
                    {
                        "ciphertext": file_rec["ciphertext"],
                        "nonce": file_rec["nonce"],
                        "wrapped_file_key": json.loads(share["wrapped_file_key"]),
                        "ephemeral_public": share["ephemeral_public"],
                    },
                    keys["x_private"],
                )
            except (InvalidTag, ValueError, KeyError, json.JSONDecodeError) as e:
                print(colour("[!] Decryption failed or ciphertext was tampered with.", RED))
                log_event(username, role, "DECRYPT_FAIL", f"file_id={share['file_id']} error={type(e).__name__}")
                continue

            pub_key = deserialise_public_key(file_rec["ed25519_public"])
            computed_hash = hashlib.sha256(plaintext).hexdigest()
            # Independently verifies the Ed25519 signature against the stored public key to guarantee authenticity
            sig_valid = (
                computed_hash == file_rec["content_hash"]
                and verify_signature(pub_key, file_rec["content_hash"].encode("utf-8"), file_rec["signature"])
            )

            print(f"\n  Content   : {plaintext.decode('utf-8')}")
            status_text = colour("VALID ✓", GREEN) if sig_valid else colour("INVALID ✗", RED)
            print(f"  Signature : {status_text}")

            log_event(username, role, "VIEW_FINDING", f"file_id={share['file_id']}")

        elif choice == "3":
            shares = get_shares_for_user(username)
            received = [
                s for s in shares
                if s["shared_with"] == username and s["shared_by"] != username
            ]

            if not received:
                print("No findings shared with you.")
                continue

            for i, s in enumerate(received):
                print(f"  [{i}] {s['filename']} from {s['shared_by']}")

            try:
                idx = int(input("Select: "))
                if not (0 <= idx < len(received)):
                    print(colour("[!] Invalid selection.", RED))
                    continue
            except ValueError:
                print(colour("[!] Enter a number.", RED))
                continue

            share = received[idx]
            file_rec = get_file(share["file_id"])

            if not file_rec:
                print(colour("[!] File record missing.", RED))
                continue

            try:
                wrapped = json.loads(share["wrapped_file_key"]) if isinstance(share["wrapped_file_key"], str) else share["wrapped_file_key"]
                plaintext = decrypt_file(
                    {
                        "ciphertext": file_rec["ciphertext"],
                        "nonce": file_rec["nonce"],
                        "wrapped_file_key": wrapped,
                        "ephemeral_public": share["ephemeral_public"],
                    },
                    keys["x_private"],
                )
            except (InvalidTag, ValueError, KeyError, json.JSONDecodeError) as e:
                print(colour("[!] Decryption failed or ciphertext was tampered with.", RED))
                log_event(username, role, "DECRYPT_FAIL", f"file_id={share['file_id']} error={type(e).__name__}")
                continue

            pub_key = deserialise_public_key(file_rec["ed25519_public"])
            computed_hash = hashlib.sha256(plaintext).hexdigest()
            sig_valid = (
                computed_hash == file_rec["content_hash"]
                and verify_signature(pub_key, file_rec["content_hash"].encode("utf-8"), file_rec["signature"])
            )

            print(f"\n  Content   : {plaintext.decode('utf-8')}")
            status_text = colour("VALID ✓", GREEN) if sig_valid else colour("INVALID ✗", RED)
            print(f"  Signature : {status_text}")

            log_event(
                username,
                role,
                "VIEW_SHARED_FINDING",
                f"file_id={share['file_id']}",
            )

        elif choice == "4":
            shares = get_shares_for_user(username)
            my_shares = [
                s for s in shares
                if s["shared_by"] == username and s["shared_with"] == username
            ]

            if not my_shares:
                print("No findings to share.")
                continue

            for i, s in enumerate(my_shares):
                print(f"  [{i}] {s['filename']}")

            try:
                idx = int(input("Select finding to share: "))
                if not (0 <= idx < len(my_shares)):
                    print(colour("[!] Invalid selection.", RED))
                    continue
            except ValueError:
                print(colour("[!] Enter a number.", RED))
                continue

            recipient = input("Share with (username): ").strip()
            recipient_user = get_user(recipient)

            if not recipient_user:
                print(colour("[!] User not found.", RED))
                continue

            if recipient_user["role"] != "researcher":
                print(colour("[!] Can only share with other researchers.", RED))
                continue

            recipient_keys = get_user_active_public_keys(recipient)
            if not recipient_keys:
                print(colour("[!] Recipient has no active keys on record.", RED))
                continue

            share = my_shares[idx]

            if share["shared_with"] != username:
                print(colour("[!] You are not authorised to re-share this item.", RED))
                log_event(username, role, "RESHARE_DENIED", f"file_id={share['file_id']}")
                continue

            try:
                if isinstance(share["wrapped_file_key"], str):
                    share = dict(share)
                    share["wrapped_file_key"] = json.loads(share["wrapped_file_key"])
                file_key = unwrap_file_key(share, keys["x_private"])
            except (InvalidTag, ValueError, KeyError, json.JSONDecodeError) as e:
                print(colour("[!] Could not unwrap file key.", RED))
                log_event(username, role, "UNWRAP_FAIL", f"file_id={share['file_id']} error={type(e).__name__}")
                continue

            recipient_x_public = deserialise_public_key(recipient_keys["x25519_public"])
            new_wrap = wrap_file_for_recipient(file_key, recipient_x_public)

            store_share(
                share_id=str(uuid.uuid4()),
                file_id=share["file_id"],
                shared_by=username,
                shared_with=recipient,
                wrapped_file_key=new_wrap["wrapped_file_key"],
                ephemeral_public=new_wrap["ephemeral_public"],
                created_at=time.time(),
            )

            log_event(username, role, "SHARE_FINDING", f"file_id={share['file_id']} with={recipient}")
            print(colour(f"[OK] Finding shared with {recipient}.", GREEN))

        elif choice == "5":
            changed = password_change_flow(username, role)
            if changed:
                break

        elif choice == "6":
            rotated = self_key_rotation_flow(username, role, password)
            if rotated:
                break
        elif choice == "7":
            log_event(username, role, "LOGOUT", "")
            print("Logged out.")
            break

        else:
            print(colour("[!] Unrecognised option.", RED))


def clinician_menu(username: str, keys: dict, session_start: float, password: str) -> None:
    role = "clinician"

    while True:
        if not check_session(session_start):
            print(colour("[!] Session expired. Please log in again.", RED))
            log_event(username, role, "SESSION_TIMEOUT", "")
            break

        print("1 Upload patient dataset")
        print("2 View my datasets")
        print("3 View datasets shared with me")
        print("4 Share a dataset with another clinician")
        print("5 Erase a dataset")
        print("6 Change password")
        print("7 Rotate my cryptographic keys")
        print("8 Logout")
        choice = input("Choice: ").strip()

        if choice == "1":
            patient_id = input("Patient ID       : ").strip()
            data_content = input("Dataset content  : ").strip()
            consent_basis = input("Consent basis    : ").strip()

            payload = json.dumps({
                "patient_id": patient_id,
                "data": data_content,
                "consent_basis": consent_basis
            }).encode("utf-8")

            content_hash = hashlib.sha256(payload).hexdigest()
            signature = sign_data(keys["ed_private"], content_hash.encode("utf-8"))
            blob = encrypt_file(payload, keys["x_public"])
            file_id = str(uuid.uuid4())
            # Hashes the patient ID to prevent storage of raw PII and enforce Data Minimisation
            patient_ref = hashlib.sha256(patient_id.encode("utf-8")).hexdigest()[:12]

            store_file(
                file_id=file_id,
                owner=username,
                role=role,
                filename=f"dataset_{patient_ref}",
                ciphertext=blob["ciphertext"],
                nonce=blob["nonce"],
                signature=signature,
                content_hash=content_hash,
                ed25519_public=serialise_public_key(keys["ed_public"]),
                created_at=time.time()
            )

            store_share(
                share_id=str(uuid.uuid4()),
                file_id=file_id,
                shared_by=username,
                shared_with=username,
                wrapped_file_key=blob["wrapped_file_key"],
                ephemeral_public=blob["ephemeral_public"],
                created_at=time.time()
            )

            patient_ref = hashlib.sha256(patient_id.encode("utf-8")).hexdigest()[:12]
            log_event(
                username,
                role,
                "UPLOAD_DATASET",
                f"file_id={file_id} subject_ref={patient_ref}"
            )

            print(colour(f"[OK] Dataset encrypted and stored. ID: {file_id}", GREEN))

        elif choice == "2":
            shares = get_shares_for_user(username)
            my_shares = [
                s for s in shares
                if s["shared_by"] == username and s["shared_with"] == username
            ]

            if not my_shares:
                print("No datasets on record.")
                continue

            for i, s in enumerate(my_shares):
                print(f"  [{i}] {s['filename']}")

            try:
                idx = int(input("Select: "))
                if not (0 <= idx < len(my_shares)):
                    print(colour("[!] Invalid selection.", RED))
                    continue
            except ValueError:
                print(colour("[!] Enter a number.", RED))
                continue

            share = my_shares[idx]
            file_rec = get_file(share["file_id"])

            if not file_rec:
                print(colour("[!] File record missing.", RED))
                continue

            try:
                wrapped = json.loads(share["wrapped_file_key"]) if isinstance(share["wrapped_file_key"], str) else share["wrapped_file_key"]
                plaintext = decrypt_file(
                    {
                        "ciphertext": file_rec["ciphertext"],
                        "nonce": file_rec["nonce"],
                        "wrapped_file_key": wrapped,
                        "ephemeral_public": share["ephemeral_public"]
                    },
                    keys["x_private"]
                )
            except (InvalidTag, ValueError, KeyError, json.JSONDecodeError) as e:
                print(colour("[!] Decryption failed or ciphertext was tampered with.", RED))
                log_event(username, role, "DECRYPT_FAIL", f"file_id={share['file_id']} error={type(e).__name__}")
                continue

            computed_hash = hashlib.sha256(plaintext).hexdigest()
            pub_key = deserialise_public_key(file_rec["ed25519_public"])
            sig_valid = (
                computed_hash == file_rec["content_hash"]
                and verify_signature(pub_key, file_rec["content_hash"].encode("utf-8"), file_rec["signature"])
            )

            parsed = json.loads(plaintext)
            print(f"\n  Patient ID    : {parsed['patient_id']}")
            print(f"  Data          : {parsed['data']}")
            print(f"  Consent basis : {parsed['consent_basis']}")
            status_text = colour("VALID ✓", GREEN) if sig_valid else colour("INVALID ✗", RED)
            print(f"  Signature     : {status_text}")

            log_event(username, role, "VIEW_DATASET", f"file_id={share['file_id']}")

        elif choice == "3":
            shares = get_shares_for_user(username)
            received = [
                s for s in shares
                if s["shared_with"] == username and s["shared_by"] != username
            ]

            if not received:
                print("No datasets shared with you.")
                continue

            for i, s in enumerate(received):
                print(f"  [{i}] {s['filename']} from {s['shared_by']}")

            try:
                idx = int(input("Select: "))
                if not (0 <= idx < len(received)):
                    print(colour("[!] Invalid selection.", RED))
                    continue
            except ValueError:
                print(colour("[!] Enter a number.", RED))
                continue

            share = received[idx]
            file_rec = get_file(share["file_id"])

            if not file_rec:
                print(colour("[!] File record missing.", RED))
                continue

            try:
                wrapped = json.loads(share["wrapped_file_key"]) if isinstance(share["wrapped_file_key"], str) else share["wrapped_file_key"]
                plaintext = decrypt_file(
                    {
                        "ciphertext": file_rec["ciphertext"],
                        "nonce": file_rec["nonce"],
                        "wrapped_file_key": wrapped,
                        "ephemeral_public": share["ephemeral_public"]
                    },
                    keys["x_private"]
                )
            except (InvalidTag, ValueError, KeyError, json.JSONDecodeError) as e:
                print(colour("[!] Decryption failed or ciphertext was tampered with.", RED))
                log_event(username, role, "DECRYPT_FAIL", f"file_id={share['file_id']} error={type(e).__name__}")
                continue

            computed_hash = hashlib.sha256(plaintext).hexdigest()
            pub_key = deserialise_public_key(file_rec["ed25519_public"])
            sig_valid = (
                computed_hash == file_rec["content_hash"]
                and verify_signature(pub_key, file_rec["content_hash"].encode("utf-8"), file_rec["signature"])
            )

            parsed = json.loads(plaintext)
            print(f"\n  Patient ID    : {parsed['patient_id']}")
            print(f"  Data          : {parsed['data']}")
            print(f"  Consent basis : {parsed['consent_basis']}")
            status_text = colour("VALID ✓", GREEN) if sig_valid else colour("INVALID ✗", RED)
            print(f"  Signature     : {status_text}")

            log_event(
                username,
                role,
                "VIEW_SHARED_DATASET",
                f"file_id={share['file_id']}"
            )

        elif choice == "4":
            shares = get_shares_for_user(username)
            my_shares = [
                s for s in shares
                if s["shared_by"] == username and s["shared_with"] == username
            ]

            if not my_shares:
                print("No datasets to share.")
                continue

            for i, s in enumerate(my_shares):
                print(f"  [{i}] {s['filename']}")

            try:
                idx = int(input("Select dataset to share: "))
                if not (0 <= idx < len(my_shares)):
                    print(colour("[!] Invalid selection.", RED))
                    continue
            except ValueError:
                print(colour("[!] Enter a number.", RED))
                continue

            recipient = input("Share with (username): ").strip()
            recipient_user = get_user(recipient)

            if not recipient_user:
                print(colour("[!] User not found.", RED))
                continue

            if recipient_user["role"] != "clinician":
                print(colour("[!] Can only share with other clinicians.", RED))
                continue

            recipient_keys = get_user_active_public_keys(recipient)
            if not recipient_keys:
                print(colour("[!] Recipient has no active keys.", RED))
                continue

            share = my_shares[idx]

            if share["shared_with"] != username:
                print(colour("[!] You are not authorised to re-share this item.", RED))
                log_event(username, role, "RESHARE_DENIED", f"file_id={share['file_id']}")
                continue

            try:
                file_key = unwrap_file_key(share, keys["x_private"])
            except (InvalidTag, ValueError, KeyError, json.JSONDecodeError) as e:
                print(colour("[!] Could not unwrap file key.", RED))
                log_event(username, role, "UNWRAP_FAIL", f"file_id={share['file_id']} error={type(e).__name__}")
                continue

            recipient_x_public = deserialise_public_key(recipient_keys["x25519_public"])
            new_wrap = wrap_file_for_recipient(file_key, recipient_x_public)

            store_share(
                share_id=str(uuid.uuid4()),
                file_id=share["file_id"],
                shared_by=username,
                shared_with=recipient,
                wrapped_file_key=new_wrap["wrapped_file_key"],
                ephemeral_public=new_wrap["ephemeral_public"],
                created_at=time.time()
            )

            log_event(username, role, "SHARE_DATASET", f"file_id={share['file_id']} with={recipient}")
            print(colour(f"[OK] Dataset shared with {recipient}.", GREEN))

        elif choice == "5":
            shares = get_shares_for_user(username)
            my_shares = [
                s for s in shares
                if s["shared_by"] == username and s["shared_with"] == username
            ]

            if not my_shares:
                print("No datasets to erase.")
                continue

            for i, s in enumerate(my_shares):
                print(f"  [{i}] {s['filename']}")

            try:
                idx = int(input("Select to erase: "))
                if not (0 <= idx < len(my_shares)):
                    print(colour("[!] Invalid selection.", RED))
                    continue
            except ValueError:
                print(colour("[!] Enter a number.", RED))
                continue

            file_id = my_shares[idx]["file_id"]
            delete_file(file_id)
            log_event(username, role, "ERASE_DATASET", f"file_id={file_id}")
            print(colour("[OK] Dataset erased.", GREEN))

        elif choice == "6":
            changed = password_change_flow(username, role)
            if changed:
                break
        elif choice == "7":
            rotated = self_key_rotation_flow(username, role, password)
            if rotated:
                break
        elif choice == "8":
            log_event(username, role, "LOGOUT", "")
            print("Logged out.")
            break

        else:
            print(colour("[!] Unrecognised option.", RED))


def auditor_menu(username: str, keys: dict, session_start: float) -> None:
    role = "auditor"

    SHOW_DETAIL_FOR = {
        "LOGIN_BLOCKED",
        "MFA_FAIL",
        "KEY_LOAD_FAIL",
        "DECRYPT_FAIL",
        "UNWRAP_FAIL",
        "RESHARE_DENIED",
        "VERIFY_LOG_INTEGRITY",
        "VERIFY_SIGNATURE",
        "ERASE_DATASET",
    }

    def get_visible_detail(entry: dict) -> str:
        action = entry.get("action", "")
        detail = entry.get("detail", "")

        if action not in SHOW_DETAIL_FOR:
            return ""

        if action == "VERIFY_SIGNATURE":
            return detail

        if action == "VERIFY_LOG_INTEGRITY":
            return detail

        if action == "LOGIN_BLOCKED":
            return detail

        if action in {"DECRYPT_FAIL", "UNWRAP_FAIL", "KEY_LOAD_FAIL"}:
            return detail

        if action == "RESHARE_DENIED":
            return "Unauthorised re-share attempt"

        if action == "ERASE_DATASET":
            return detail

        if action == "MFA_FAIL":
            return "Invalid MFA code"

        return ""

    while True:
        if not check_session(session_start):
            print(colour("[!] Session expired.", RED))
            log_event(username, role, "SESSION_TIMEOUT", "")
            break

        print("\n--- Auditor Menu ---")
        print("1 View audit log")
        print("2 Verify audit log integrity")
        print("3 Verify a signature")
        print("4 Change password")
        print("5 Logout")
        choice = input("Choice: ").strip()

        if choice == "1":
            entries = read_log()

            if not entries:
                print("Audit log is empty.")
            else:
                visible_rows = []
                for e in entries:
                    visible_rows.append({
                        "timestamp": e.get("timestamp", ""),
                        "user": e.get("user", ""),
                        "role": e.get("role", ""),
                        "action": e.get("action", ""),
                        "detail": get_visible_detail(e),
                    })

                has_detail = any(row["detail"] for row in visible_rows)

                if has_detail:
                    print(f"\n{'Timestamp':<22} {'User':<18} {'Role':<12} {'Action':<35} Detail")
                    print("-" * 110)
                    for row in visible_rows:
                        print(
                            f"  {row['timestamp']:<20} "
                            f"{row['user']:<18} "
                            f"{row['role']:<12} "
                            f"{row['action']:<35} "
                            f"{row['detail']}"
                        )
                else:
                    print(f"\n{'Timestamp':<22} {'User':<18} {'Role':<12} {'Action':<35}")
                    print("-" * 95)
                    for row in visible_rows:
                        print(
                            f"  {row['timestamp']:<20} "
                            f"{row['user']:<18} "
                            f"{row['role']:<12} "
                            f"{row['action']:<35}"
                        )

            log_event(username, role, "VIEW_AUDIT_LOG", "")

        elif choice == "2":
            valid, tampered_at = verify_log_integrity()
            if valid:
                print(colour("[OK] Log chain intact.", GREEN))
            else:
                print(colour(f"[WARN] Chain broken at entries: {tampered_at}", RED))

            log_event(username, role, "VERIFY_LOG_INTEGRITY", f"valid={valid}")

        elif choice == "3":
            all_files = get_files_for_role("researcher") + get_files_for_role("clinician")

            if not all_files:
                print("No signed files on record.")
                continue

            for i, f in enumerate(all_files):
                label = f["filename"] if f["role"] == "researcher" else f["file_id"][:8]
                print(f"  [{i}] {label} by {f['owner']} ({f['role']})")

            try:
                idx = int(input("Select file: "))
                if not (0 <= idx < len(all_files)):
                    print(colour("[!] Invalid selection.", RED))
                    continue
            except ValueError:
                print(colour("[!] Enter a number.", RED))
                continue

            file_rec = all_files[idx]
            pub_key = deserialise_public_key(file_rec["ed25519_public"])
            sig_valid = verify_signature(
                pub_key,
                file_rec["content_hash"].encode("utf-8"),
                file_rec["signature"]
            )

            print()
            print(f"File ID    : {file_rec['file_id']}")
            print(f"Owner      : {file_rec['owner']}")
            print(f"Role       : {file_rec['role']}")

            if file_rec["role"] == "researcher":
                print(f"Finding    : {file_rec['filename']}")
            else:
                print(f"File Ref   : {file_rec['file_id'][:8]}")

            hash_short = file_rec["content_hash"][:16] + "..."
            print(f"Hash       : {hash_short}")
            status_text = colour("VALID ✓", GREEN) if sig_valid else colour("INVALID ✗", RED)
            print(f"Signature  : {status_text}")

            log_event(
                username,
                role,
                "VERIFY_SIGNATURE",
                f"file_id={file_rec['file_id']} valid={sig_valid}"
            )

        elif choice == "4":
            changed = password_change_flow(username, role)
            if changed:
                break
        elif choice == "5":
            log_event(username, role, "LOGOUT", "")
            print("Logged out.")
            break

        else:
            print(colour("[!] Unrecognised option.", RED))
# Restricts admin functions and prevents self-lockout
def admin_menu(username: str, keys: dict, session_start: float, password: str) -> None:
    role = "admin"

    while True:
        if not check_session(session_start):
            print(colour("[!] Session expired. Please log in again.", RED))
            log_event(username, role, "SESSION_TIMEOUT", "")
            break

        print("\n--- Admin Menu ---")
        print("1 List users")
        print("2 Create new user")
        print("3 Disable user")
        print("4 Enable user")
        print("5 Export system backup")
        print("6 Change password")
        print("7 Logout")
        choice = input("Choice: ").strip()

        if choice == "1":
            users = list_users()

            if not users:
                print("No users found.")
                continue

            print(f"\n{'Username':<18} {'Role':<12} {'Status':<10} {'Name':<24}{'Location':<18}{'Pwd Changed'}")
            print("-" * 80)
            for u in users:
                full_name = f"{u.get('first_name', '')} {u.get('last_name', '')}".strip()
                pwd_changed_text = format_timestamp(u.get("password_changed_at"))
                print(
                    f"{u['username']:<18} "
                    f"{u['role']:<12} "
                    f"{u.get('account_status', 'active'):<10} "
                    f"{full_name:<24} "
                    f"{u.get('location', ''):<18}"
                    f"{pwd_changed_text}"
                )

            log_event(username, role, "LIST_USERS", "")

        elif choice == "2":
            user_creation_flow(created_by=username, creator_role=role, admin_mode=True)

        elif choice == "3":
            target = input("Username to disable: ").strip()

            if target == username:
                print(colour("[!] You cannot disable your own admin account.", RED))
                continue

            target_user = get_user(target)
            if not target_user:
                print(colour("[!] User not found.", RED))
                continue

            if target_user.get("account_status") != "active":
                print(colour("[!] User is already not active.", RED))
                continue

            update_user_status(target, "inactive")
            print(colour(f"[OK] User '{target}' has been disabled.", GREEN))
            log_event(username, role, "DISABLE_USER", f"user={target}")

        elif choice == "4":
            target = input("Username to enable: ").strip()

            target_user = get_user(target)
            if not target_user:
                print(colour("[!] User not found.", RED))
                continue

            if target_user.get("account_status") == "active":
                print(colour("[!] User is already active.", RED))
                continue

            update_user_status(target, "active")
            print(colour(f"[OK] User '{target}' has been enabled.", GREEN))
            log_event(username, role, "ENABLE_USER", f"user={target}")

        elif choice == "5":
            export_backup(username, role)

        elif choice == "6":
            changed = password_change_flow(username, role)
            if changed:
                break
        elif choice == "7":
            log_event(username, role, "LOGOUT", "")
            print("Logged out.")
            break
        else:
            print(colour("[!] Unrecognised option.", RED))

def main():
    initialise_db()

    if not get_user("admin"):
        print(colour("[SETUP] No admin account found. Create the built-in admin now.", YELLOW))
        while True:
            admin_password = getpass.getpass("Set admin password : ")
            confirm_password = getpass.getpass("Confirm admin password : ")

            if admin_password != confirm_password:
                print(colour("[!] Passwords do not match.", RED))
                continue

            try:
                admin_totp = register_user(
                    username="admin",
                    password=admin_password,
                    role="admin",
                    first_name="System",
                    last_name="Administrator",
                    location="Internal",
                )
                log_event("SYSTEM", "admin", "BOOTSTRAP_ADMIN_CREATED", "user=admin")
                print(colour("[OK] Built-in admin account created.", GREEN))
                print(colour(f"[!] Admin TOTP secret: {admin_totp}", YELLOW))
                break
            except ValueError as e:
                print(colour(f"[!] {e}", RED))

    print("=" * 60)
    print(colour(f"  {PLATFORM_NAME}", BOLD + CYAN))
    print(f"  {PLATFORM_TAGLINE}")
    print("=" * 60)

    while True:
        print("\n  1  Login")
        print("  2  Register new account")
        print("  3  Exit")
        opt = input("Option: ").strip()

        if opt == "3":
            print("Goodbye.")
            break

        if opt == "2":
            user_creation_flow()
            continue

        if opt != "1":
            print(colour("[!] Unrecognised option.", RED))
            continue

        username = input("Username : ").strip()
        password = getpass.getpass("Password : ")
        result = authenticate(username, password)

        if result is None:
            print(colour("[!] Login failed. Check your credentials.", RED))
            log_event(username, "unknown", "LOGIN_FAIL", "")
            continue

        if isinstance(result, str) and result.startswith("locked:"):
            remaining = result.split(":")[1]
            print(colour(f"[!] Account locked. Try again in {remaining} seconds.", RED))
            log_event(username, "unknown", "LOGIN_BLOCKED", f"locked_for={remaining}s")
            continue

        user = result
        role = user["role"]

        display_current_otp(user, username)

        totp_token = input("Authenticator code : ").strip()
        if not verify_totp(username, totptoken := totp_token):
            print(colour("[!] Invalid authenticator code.", RED))
            log_event(username, role, "MFA_FAIL", "")
            continue

        try:
            keys = load_active_user_keys(username, password)
        except Exception as e:
            print(colour(f"[!] Key loading failed: {e}", RED))
            log_event(username, role, "KEY_LOAD_FAIL", type(e).__name__)
            continue

        session_start = time.time()
        display_name = f"{user.get('first_name', '')} {user.get('last_name', '')}".strip() or username

        print(colour(f"\n[+] Welcome, {display_name}", GREEN))
        print(f"Role     : {role}")
        print(f"Location : {user.get('location', 'Not set')}")

        log_event(username, role, "LOGIN_SUCCESS", "mfa_ok")

        if role == "researcher":
            researcher_menu(username, keys, session_start, password)
        elif role == "clinician":
            clinician_menu(username, keys, session_start, password)
        elif role == "auditor":
            auditor_menu(username, keys, session_start)
        elif role == "admin":
            admin_menu(username, keys, session_start, password)
        else:
            print(colour("[!] Unrecognised role.", RED))
            log_event(username, role, "ACCESS_DENIED", "")


if __name__ == "__main__":
    main()