# config.py
# System-wide constants for the platform.

DB_FILE = "clinical_platform.db"

SESSION_TIMEOUT_SECONDS = 900   # 15 minutes
MAX_FAILED_ATTEMPTS = 3
LOCKOUT_DURATION = 300          # 5 minutes in seconds

TOTP_ISSUER = "ClinicalResearchPlatform"

# Argon2id parameters (OWASP 2023 / RFC 9106 style settings).
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536
ARGON2_PARALLELISM = 4 