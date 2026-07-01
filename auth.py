# auth.py
# Registration, password verification, TOTP, account lockout, and password change.

import time
import re
import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

from storage import (
    create_user,
    get_user,
    update_password_hash,
    update_failed_attempts,
    reset_failed_attempts,
)
from key_manager import create_initial_keys, rewrap_all_user_private_keys
from config import (
    ARGON2_TIME_COST,
    ARGON2_MEMORY_COST,
    ARGON2_PARALLELISM,
    MAX_FAILED_ATTEMPTS,
    LOCKOUT_DURATION,
    TOTP_ISSUER,
)

ph = PasswordHasher(
    time_cost=ARGON2_TIME_COST,
    memory_cost=ARGON2_MEMORY_COST,
    parallelism=ARGON2_PARALLELISM,
)

VALID_ROLES = {"researcher", "clinician", "auditor", "admin"}

# Enforces high entropy constraints to mitigate dictionary attacks
def validate_password_strength(password: str) -> None:
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters long.")
    if not re.search(r"[A-Z]", password):
        raise ValueError("Password must contain at least one uppercase letter.")
    if not re.search(r"[a-z]", password):
        raise ValueError("Password must contain at least one lowercase letter.")
    if not re.search(r"\d", password):
        raise ValueError("Password must contain at least one digit.")
    if not re.search(r"[!@#$%^&*()_\-+=\[\]{};':\"\\|,.<>/?]", password):
        raise ValueError("Password must contain at least one special character.")

# Enforces password complexity, hashes with Argon2id, and provisions MFA
def register_user(
    username: str,
    password: str,
    role: str,
    first_name: str = "",
    last_name: str = "",
    location: str = "",
) -> str:
    if role not in VALID_ROLES:
        raise ValueError(f"Invalid role: {role}")

    if get_user(username):
        raise ValueError(f"Username '{username}' already exists.")

    validate_password_strength(password)

    password_hash = ph.hash(password)
    totp_secret = pyotp.random_base32()
    now = time.time()

    create_user(
        username=username,
        password_hash=password_hash,
        role=role,
        totp_secret=totp_secret,
        created_at=now,
        first_name=first_name,
        last_name=last_name,
        location=location,
    )

    create_initial_keys(username, password)
    return totp_secret


def get_totp_uri(username: str, secret: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(
        name=username,
        issuer_name=TOTP_ISSUER,
    )


def verify_totp(username: str, token: str) -> bool:
    user = get_user(username)
    if not user or user.get("account_status") != "active":
        return False
    return pyotp.TOTP(user["totp_secret"]).verify(token, valid_window=1)

# Verifies Argon2id hash and enforces temporary lockout on max failures
def authenticate(username: str, password: str):
    user = get_user(username)
    if not user:
        return None

    if user.get("account_status", "active") != "active":
        return None

    if user["locked_until"] > time.time():
        remaining = int(user["locked_until"] - time.time())
        return f"locked:{remaining}"

    try:
        ph.verify(user["password_hash"], password)
        reset_failed_attempts(username)
        return user
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        attempts = user["failed_attempts"] + 1
        locked_until = 0

        if attempts >= MAX_FAILED_ATTEMPTS:
            locked_until = time.time() + LOCKOUT_DURATION

        update_failed_attempts(username, attempts, locked_until)
        return None

# Authenticates current password before re-wrapping keys under the new KEK
def change_password(username: str, old_password: str, new_password: str):
    user = get_user(username)
    if not user:
        raise ValueError("User not found.")

    try:
        ph.verify(user["password_hash"], old_password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        raise ValueError("Current password is incorrect.")
    if old_password == new_password:
        raise ValueError("New password must be different from the current password.")
    validate_password_strength(new_password)

    rewrap_all_user_private_keys(username, old_password, new_password)
    update_password_hash(username, ph.hash(new_password)) 