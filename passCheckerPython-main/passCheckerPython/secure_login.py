"""Secure Login System with Password Strength Validation and OTP (MFA)

Objectives Implemented:
1. Password strength validation using regular expressions.
2. Generation and verification of a one-time password (OTP) for second-factor authentication.
3. Demonstrates the principle of Multi-Factor Authentication (MFA):
   - Factor 1: Something you KNOW (username + password)
   - Factor 2: Something you HAVE (a transient OTP delivered via an out-of-band channel; here we simulate by printing it)

Usage (interactive):
    python secure_login.py

Optional flags:
    --demo      Run a non-interactive demonstration flow.

Security Notes:
- Passwords are stored only as salted PBKDF2-HMAC hashes (never in plaintext).
- OTP codes are 6-digit numeric values, cryptographically generated, expiring after a short window.
- Rate-limiting is applied for password attempts and OTP attempts.

This is an educational example and omits production concerns such as secure secret delivery, audit logs, lockout policies, and anti-enumeration strategies.
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import secrets
import sys
import time
import hashlib
import base64
import datetime
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple, Any, List

# Optional TOTP support
try:
    import pyotp  # type: ignore
except ImportError:  # pragma: no cover - handled gracefully if not installed
    pyotp = None  # type: ignore

# Add near top of secure_login.py
RECOVERY_DEBUG = True  # set False to disable debug prints

# ----------------------------- Central Configuration ---------------------------
CONFIG = {
    "pbkdf2_iterations": 200_000,
    "salt_len": 16,
    "otp_ttl": 300,
    "max_login_attempts": 5,
    "lockout_duration": 500000,               # 0 => suspend until password reset
    "password_history_depth": 3,
    "username_max_len": 32,
    "email_max_len": 254,
    "full_name_max_len": 80,
    "custom_question_max_len": 120,
    "ip_placeholder": "127.0.0.1",
    "audit_log_file": "auth_audit.log"
}

# Backwards-compatible aliases
_PBKDF2_ITER = CONFIG["pbkdf2_iterations"]
_SALT_LEN = CONFIG["salt_len"]

# Validation regexes and control char filter
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")
_EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}\.[^@\s]{2,}$")
_FULLNAME_RE = re.compile(r"[A-Za-z' -]+(?: [A-Za-z' -]+)+$")

# ----------------------------- Password Policy ---------------------------------
PASSWORD_POLICY = {
    "min_length": 8,
    "uppercase": 1,
    "lowercase": 1,
    "digits": 1,
    "special": 1,
    "allowed_specials": r"!@#$%^&*()_+\-={}\[\]:;\"'`~<>,.?/\\|"  # used for explanation only
}

PASSWORD_REGEX = re.compile(
    r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{%d,}$" % PASSWORD_POLICY["min_length"]
)

_SECURITY_QUESTIONS = [
    "What is your mother's maiden name?",
    "What was the name of your first pet?",
    "In what city were you born?"
]

# ----------------------------- User Store (In-Memory) --------------------------
# For persistence across runs, replace with file or database. Here we show a JSON file cache.
USER_STORE_FILE = "users.json"

@dataclass
class UserRecord:
    username: str
    password_hash: str  # format: algo$iterations$salt_hex$hash_hex
    totp_secret: Optional[str] = None  # presence enables TOTP second factor
    full_name: Optional[str] = None
    email: Optional[str] = None
    sec_question: Optional[str] = None
    sec_answer_hash: Optional[str] = None
    failed_attempts: int = 0
    lock_until: Optional[float] = None
    suspended: bool = False
    password_history: List[str] = field(default_factory=list)

# ----------------------------- Helper Functions --------------------------------

def load_users() -> Dict[str, UserRecord]:
    """Load users from the JSON user store.

    Returns:
        Dict[str, UserRecord]: Mapping of username -> UserRecord. Empty dict on error/missing file.
    Notes:
        Swallows broad exceptions intentionally for a smooth classroom demo. In production,
        handle JSON errors explicitly and log them.
    """
    if not os.path.exists(USER_STORE_FILE):
        return {}
    try:
        with open(USER_STORE_FILE, "r", encoding="utf-8") as f:
            raw = json.load(f)
        users: Dict[str, UserRecord] = {}
        for u, data in raw.items():
            users[u] = UserRecord(
                username=u,
                password_hash=data.get("password_hash", ""),
                totp_secret=data.get("totp_secret"),
                full_name=data.get("full_name"),
                email=data.get("email"),
                sec_question=data.get("sec_question"),
                sec_answer_hash=data.get("sec_answer_hash"),
                failed_attempts=data.get("failed_attempts", 0),
                lock_until=data.get("lock_until"),
                suspended=data.get("suspended", False),
                password_history=data.get("password_history", [])
            )
        return users
    except Exception:
        return {}

def save_users(users: Dict[str, UserRecord]) -> None:
    """Persist all users to disk in JSON format.

    Args:
        users: Mapping of usernames to UserRecord.
    Security:
        TOTP secrets are stored in plain text here (educational simplification). In real systems,
        encrypt or store secrets in a dedicated secrets manager.
    """
    serializable = {
        u: {
            "password_hash": rec.password_hash,
            "totp_secret": rec.totp_secret,
            "full_name": rec.full_name,
            "email": rec.email,
            "sec_question": rec.sec_question,
            "sec_answer_hash": rec.sec_answer_hash,
            "failed_attempts": rec.failed_attempts,
            "lock_until": rec.lock_until,
            "suspended": rec.suspended,
            "password_history": rec.password_history
        }
        for u, rec in users.items()
    }
    with open(USER_STORE_FILE, "w", encoding="utf-8") as f:
        json.dump(serializable, f, indent=2)

# ----------------------------- Audit Logging -----------------------------------

def audit_event(event: str, username: str = "unknown", details: Optional[Dict[str, Any]] = None) -> None:
    entry = {
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "event": event,
        "username": username or "unknown",
        "ip": CONFIG["ip_placeholder"],
        "details": details or {}
    }
    try:
        with open(CONFIG["audit_log_file"], "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, separators=(",", ":"), ensure_ascii=False) + "\n")
    except Exception:
        if RECOVERY_DEBUG:
            print("[AUDIT-DEBUG] failed to write audit log")

# ----------------------------- Input Sanitization ------------------------------

def sanitize_input(text: str, *, field_name: str, max_len: int) -> str:
    if text is None:
        raise ValueError("empty")
    s = text.strip()
    if len(s) == 0 or len(s) > max_len:
        raise ValueError(f"{field_name} length")
    if _CONTROL_CHARS_RE.search(s):
        raise ValueError(f"{field_name} contains control characters")
    return s

# ----------------------------- Password Hashing --------------------------------

def hash_password(password: str, *, iterations: int = 130_000) -> str:
    """Return a salted PBKDF2-HMAC-SHA256 hash string.

    Format: ``pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>``

    Args:
        password: Plaintext password (never stored)
        iterations: PBKDF2 iteration count (tunable work factor)
    Returns:
        Parameterized encoded hash string that includes algorithm, iteration count, salt and hash.
    """
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return f"pbkdf2_sha256${iterations}${salt.hex()}${dk.hex()}"

def verify_password(password: str, stored: str) -> bool:
    """Verify a password against a stored PBKDF2 hash string.

    Args:
        password: Candidate plaintext password.
        stored: Stored hash produced by ``hash_password``.
    Returns:
        True if the password matches; False otherwise or on parse error.
    """
    try:
        algo, iterations_s, salt_hex, hash_hex = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        iterations = int(iterations_s)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
        test = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
        # constant-time compare
        return secrets.compare_digest(expected, test)
    except Exception:
        return False

def compute_password_hash(password: str) -> str:
    try:
        return hash_password(password)  # reuse if implemented in file
    except Exception:
        salt = secrets.token_bytes(CONFIG["salt_len"])
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, CONFIG["pbkdf2_iterations"])
        return base64.b64encode(salt + dk).decode("utf-8")

def password_hashes_equal(stored_b64: str, candidate_password: str) -> bool:
    try:
        return verify_password(stored_b64, candidate_password)  # reuse if available
    except Exception:
        try:
            data = base64.b64decode(stored_b64.encode("utf-8"))
            salt = data[:CONFIG["salt_len"]]
            dk_stored = data[CONFIG["salt_len"]:]
            dk_check = hashlib.pbkdf2_hmac("sha256", candidate_password.encode("utf-8"), salt, CONFIG["pbkdf2_iterations"])
            return secrets.compare_digest(dk_stored, dk_check)
        except Exception:
            return False

# ----------------------------- Password Validation -----------------------------

def validate_password(password: str) -> Tuple[bool, str]:
    """Validate password strength against policy.

    Args:
        password: Candidate password.
    Returns:
        (ok, message) where ok indicates policy pass and message provides feedback.
    """
    if not PASSWORD_REGEX.match(password):
        reasons = []
        if len(password) < PASSWORD_POLICY["min_length"]:
            reasons.append(f"at least {PASSWORD_POLICY['min_length']} characters")
        if not re.search(r"[A-Z]", password):
            reasons.append("an uppercase letter")
        if not re.search(r"[a-z]", password):
            reasons.append("a lowercase letter")
        if not re.search(r"\d", password):
            reasons.append("a digit")
        if not re.search(r"[^A-Za-z0-9]", password):
            reasons.append("a special character")
        return False, "Password must contain: " + ", ".join(reasons)
    return True, "Strong password."

# ----------------------------- Validation Helpers ------------------------------

def validate_full_name(full_name: str) -> bool:
    try:
        s = sanitize_input(full_name, field_name="full_name", max_len=CONFIG["full_name_max_len"])
    except ValueError:
        return False
    return bool(_FULLNAME_RE.fullmatch(s))

def validate_email(email: str) -> bool:
    try:
        s = sanitize_input(email, field_name="email", max_len=CONFIG["email_max_len"])
    except ValueError:
        return False
    return bool(_EMAIL_RE.fullmatch(s))

def is_email_unique(users: Dict[str, Any], email: str) -> bool:
    low = email.strip().lower()
    for u in users.values():
        uemail = getattr(u, "email", None)
        if uemail and uemail.strip().lower() == low:
            return False
    return True

# ----------------------------- Security Answer PBKDF2 --------------------------

def _hash_answer_pbkdf2(answer: str) -> str:
    """Return base64(salt + dk). Normalizes answer to lower-case and strips spaces."""
    normalized = answer.strip().lower().encode("utf-8")
    salt = secrets.token_bytes(CONFIG["salt_len"])
    dk = hashlib.pbkdf2_hmac("sha256", normalized, salt, CONFIG["pbkdf2_iterations"])
    return base64.b64encode(salt + dk).decode("utf-8")

def _verify_answer_pbkdf2(stored_b64: str, answer: str) -> bool:
    try:
        data = base64.b64decode(stored_b64.encode("utf-8"))
        salt = data[:CONFIG["salt_len"]]
        dk_stored = data[CONFIG["salt_len"]:]
        normalized = answer.strip().lower().encode("utf-8")
        dk_check = hashlib.pbkdf2_hmac("sha256", normalized, salt, CONFIG["pbkdf2_iterations"])
        return secrets.compare_digest(dk_stored, dk_check)
    except Exception:
        return False

# ----------------------------- Security Question Enrollment --------------------

def _choose_security_question() -> str:
    print("Choose a security question or enter a custom one:")
    for i, q in enumerate(_SECURITY_QUESTIONS, start=1):
        print(f" {i}. {q}")
    print(f" {len(_SECURITY_QUESTIONS)+1}. Enter custom question")
    choice = input("Select number: ").strip()
    if choice.isdigit():
        idx = int(choice)
        if 1 <= idx <= len(_SECURITY_QUESTIONS):
            return _SECURITY_QUESTIONS[idx - 1]
        if idx == len(_SECURITY_QUESTIONS) + 1:
            custom = input(f"Enter custom question (max {CONFIG['custom_question_max_len']} chars): ").strip()
            if not custom or len(custom) > CONFIG["custom_question_max_len"]:
                print("Invalid custom question length.")
                return _choose_security_question()
            # sanitize custom question
            try:
                return sanitize_input(custom, field_name="custom_question", max_len=CONFIG["custom_question_max_len"])
            except ValueError:
                print("Invalid custom question.")
                return _choose_security_question()
    print("Invalid selection.")
    return _choose_security_question()

def _prompt_and_store_security_answer() -> str:
    while True:
        ans1 = input("Security answer (will not be stored plaintext): ").strip()
        ans2 = input("Confirm security answer: ").strip()
        if ans1 != ans2:
            print("Answers do not match. Try again.")
            continue
        if len(ans1) == 0:
            print("Answer cannot be empty.")
            continue
        return _hash_answer_pbkdf2(ans1)

# ----------------------------- OTP Management ----------------------------------
@dataclass
class OTPRecord:
    code: str
    expires_at: float
    attempts_left: int

OTP_LENGTH = 6
OTP_TTL_SECONDS = 120  # 2 minutes
OTP_MAX_ATTEMPTS = 3

_active_otps: Dict[str, OTPRecord] = {}

def generate_otp(username: str) -> str:
    """Generate and store a single-use numeric OTP for a user.

    Args:
        username: User identifier.
    Returns:
        The generated 6-digit code (returned for simulation; would be sent out-of-band in production).
    Side Effects:
        Creates/overwrites an OTPRecord in the in-memory store with expiry & attempt counter.
    """
    code = ''.join(secrets.choice('0123456789') for _ in range(OTP_LENGTH))
    _active_otps[username] = OTPRecord(code=code, expires_at=time.time() + OTP_TTL_SECONDS, attempts_left=OTP_MAX_ATTEMPTS)
    return code

def verify_otp(username: str, code: str) -> bool:
    """Validate a submitted OTP for a user.

    Args:
        username: User identifier.
        code: Submitted OTP string.
    Returns:
        True if valid (and consumes it). False if invalid, expired, or attempts exceeded.
    """
    rec = _active_otps.get(username)
    if not rec:
        return False
    if time.time() > rec.expires_at:
        del _active_otps[username]
        return False
    if rec.attempts_left <= 0:
        del _active_otps[username]
        return False
    rec.attempts_left -= 1
    if secrets.compare_digest(rec.code, code):
        del _active_otps[username]
        return True
    if rec.attempts_left <= 0:
        del _active_otps[username]
    return False

def _invalidate_active_otp_for_user(username: str):
    try:
        if '_active_otps' in globals():
            _active_otps.pop(username, None)
    except Exception:
        pass
    try:
        if '_active_totp_sessions' in globals():
            _active_totp_sessions.pop(username, None)
    except Exception:
        pass

# ----------------------------- Account Lock/Suspend Helpers -------------------

def is_account_locked(user: UserRecord) -> bool:
    if getattr(user, "suspended", False):
        return True
    lu = getattr(user, "lock_until", None)
    if lu and time.time() < float(lu):
        return True
    return False

def set_lock_after_failed_attempt(user: UserRecord, users: Dict[str, UserRecord]) -> None:
    user.failed_attempts = getattr(user, "failed_attempts", 0) + 1
    if user.failed_attempts >= CONFIG["max_login_attempts"]:
        duration = CONFIG["lockout_duration"]
        if duration == 0:
            user.suspended = True
            user.lock_until = None
            audit_event("lockout", username=user.username, details={"type": "suspended_until_reset"})
        else:
            user.lock_until = time.time() + duration
            audit_event("lockout", username=user.username, details={"lock_until": user.lock_until})
    save_users(users)

# ----------------------------- Core Flows --------------------------------------

def _is_password_in_history(user: Any, new_hash: str) -> bool:
    hist = getattr(user, "password_history", None)
    if hist is None:
        return False
    try:
        return any(h == new_hash for h in hist)
    except Exception:
        return False

def _prepend_password_history(user: Any, new_hash: str) -> None:
    hist = getattr(user, "password_history", None) or []
    # remove duplicates of new_hash, prepend, trim to depth
    hist = [new_hash] + [h for h in hist if h != new_hash]
    depth = CONFIG.get("password_history_depth", 3)
    try:
        if isinstance(user, dict):
            user["password_history"] = hist[:depth]
        else:
            user.password_history = hist[:depth]
    except Exception:
        # best-effort
        pass

def register(users: Dict[str, Any]):
    """Register new user extended with full_name, email, and security question/answer."""
    print("=== Register a new account ===")
    try:
        username = sanitize_input(input("Username: "), field_name="username", max_len=CONFIG["username_max_len"])
    except ValueError:
        print("Invalid username.")
        return

    if username in users:
        print("Username already exists.")
        return

    # Password collection reusing existing validate_password if available
    for _ in range(5):
        pwd = getpass.getpass("Password: ")
        pwd2 = getpass.getpass("Confirm password: ")
        if pwd != pwd2:
            print("Passwords do not match.")
            continue
        ok, msg = validate_password(pwd)
        if not ok:
            print(msg)
            continue
        break
    else:
        print("Failed to set password.")
        return

    # Full name
    while True:
        full_name = input("Full name (first and last): ").strip()
        if not validate_full_name(full_name):
            print("Enter at least two words, alphabetic characters, spaces, hyphen or apostrophe allowed.")
            continue
        break

    # Email
    while True:
        email = input("Email address: ").strip()
        if not validate_email(email):
            print("Invalid email format.")
            continue
        if not is_email_unique(users, email):
            print("Email already in use.")
            continue
        break

    # Security question & answer
    question = _choose_security_question()
    answer_hash = _prompt_and_store_security_answer()

    # Create user object
    pwd_hash = compute_password_hash(pwd)
    try:
        user_obj = UserRecord(username=username, password_hash=pwd_hash)
        user_obj.full_name = full_name
        user_obj.email = email
        user_obj.sec_question = question
        user_obj.sec_answer_hash = answer_hash
        user_obj.password_history = [pwd_hash]
        users[username] = user_obj
    except Exception:
        print("Registration failed.")
        return

    save_users(users)
    audit_event("register", username=username)
    print("Registration complete. You can now login.")

def forgot_password(users: Dict[str, Any]):
    """Robust forgot-password flow: case-insensitive lookup and dict/object compatibility.
    Keeps generic failure messages and audits; clears suspension only on successful reset.
    """
    print("=== Account Recovery ===")
    try:
        username = sanitize_input(input("Enter username: "), field_name="username", max_len=CONFIG["username_max_len"])
    except ValueError:
        print("Recovery failed.")
        return

    user = users.get(username)
    if not user:
        time.sleep(0.3)
        audit_event("reset_start", username="unknown")
        print("Recovery failed.")
        return

    question = getattr(user, "sec_question", None) if not isinstance(user, dict) else user.get("sec_question")
    stored_hash = getattr(user, "sec_answer_hash", None) if not isinstance(user, dict) else user.get("sec_answer_hash")
    if not question or not stored_hash:
        audit_event("reset_start", username=username, details={"reason": "no_security_question"})
        print("Recovery failed.")
        return

    print("Security question:")
    print(question)
    answer = input("Answer: ").strip()
    if not _verify_answer_pbkdf2(stored_hash, answer):
        audit_event("reset_start", username=username, details={"reason": "bad_answer"})
        print("Recovery failed.")
        return

    audit_event("reset_verified", username=username)
    for _ in range(5):
        new_pwd = getpass.getpass("New password: ")
        new_pwd2 = getpass.getpass("Confirm new password: ")
        if new_pwd != new_pwd2:
            print("Passwords do not match.")
            continue
        ok, msg = validate_password(new_pwd)
        if not ok:
            print(msg)
            continue

        new_hash = compute_password_hash(new_pwd)
        # check history (dict or object)
        history = user.get("password_history") if isinstance(user, dict) else getattr(user, "password_history", None)
        if history is None:
            history = []

        if any(h == new_hash for h in history):
            print("Cannot reuse recent password.")
            continue

        # update stored hash and history
        if isinstance(user, dict):
            user["password_hash"] = new_hash
        else:
            user.password_hash = new_hash
        _prepend_password_history(user, new_hash)

        # clear locks/suspension and failed attempts
        if isinstance(user, dict):
            user["failed_attempts"] = 0
            user["lock_until"] = None
            user["suspended"] = False
        else:
            user.failed_attempts = 0
            user.lock_until = None
            user.suspended = False

        _invalidate_active_otp_for_user(username)
        users[username] = user
        save_users(users)
        audit_event("reset_success", username=username)
        print("Password reset successful. You may now log in with your new password.")
        return

    audit_event("reset_fail", username=username)
    print("Recovery failed.")

def login(users: Dict[str, UserRecord]) -> Optional[str]:
    """Interactive primary-factor authentication (username + password).

    Uses per-user failed_attempts and suspended flag:
      - On wrong password increments failed_attempts and persists.
      - If failed_attempts >= LOGIN_MAX_ATTEMPTS sets suspended=True and persists.
      - If suspended is True, denies login until password reset (forgot_password clears it).
    Returns:
        Username on successful password verification; None if attempts exhausted or failure.
    """
    print("=== Login ===")
    try:
        username = sanitize_input(input("Username: "), field_name="username", max_len=CONFIG["username_max_len"])
    except ValueError:
        print("Authentication failed.")
        return None

    user = users.get(username)
    if not user:
        audit_event("login_fail", username="unknown", details={"reason": "bad_credentials"})
        print("Authentication failed.")
        return None

    if is_account_locked(user):
        audit_event("login_fail", username=username, details={"reason": "locked_or_suspended"})
        print("You're suspended from logging in for a moment; please try again later.")
        return None

    pwd = getpass.getpass("Password: ")
    if password_hashes_equal(getattr(user, "password_hash", ""), pwd):
        user.failed_attempts = 0
        user.lock_until = None
        user.suspended = False
        save_users(users)
        audit_event("login_success", username=username)
        print("Login successful.")
        return username

    set_lock_after_failed_attempt(user, users)
    audit_event("login_fail", username=username, details={"reason": "bad_credentials"})
    print("Authentication failed.")
    return None

def second_factor(username: str, user: UserRecord) -> bool:
    """Perform second factor verification.

    Selection Logic:
        - If user has a TOTP secret and `pyotp` is available -> prompt for rolling TOTP.
        - Otherwise -> generate & validate a fallback single-use OTP.
    Returns:
        True if second factor succeeds; False otherwise.
    """
    if user.totp_secret and pyotp:
        print("=== TOTP Verification (MFA Second Factor) ===")
        totp = pyotp.TOTP(user.totp_secret)
        for attempt in range(3):
            code = input("Enter current 6-digit TOTP (or 'q' to cancel): ").strip()
            if code.lower() == 'q':
                return False
            if totp.verify(code, valid_window=1):  # allow slight clock skew
                print("TOTP verified. Login successful.\n")
                return True
            else:
                print(f"Invalid TOTP. Attempts left: {2 - attempt}")
        print("Failed TOTP verification.")
        return False
    # Fallback OTP flow
    print("=== OTP Verification (MFA Second Factor) ===")
    otp = generate_otp(username)
    print(f"[Simulation] OTP for {username}: {otp}")
    while True:
        code = input("Enter the 6-digit OTP (or 'q' to cancel): ").strip()
        if code.lower() == 'q':
            return False
        if verify_otp(username, code):
            print("OTP verified. Login successful.\n")
            return True
        else:
            print("Invalid or expired OTP.")
            if username not in _active_otps:
                print("OTP no longer valid. Restart login.")
                return False
            else:
                rec = _active_otps[username]
                print(f"Attempts left for this OTP: {rec.attempts_left}")

# ----------------------------- Demo & CLI --------------------------------------

def interactive_main():
    """Main interactive loop presenting the menu and dispatching user choices."""
    users = load_users()
    menu = {
        '1': ("Register", lambda: register(users)),
        '2': ("Login", lambda: handle_login(users) if 'handle_login' in globals() else login(users)),
        '3': ("Enroll TOTP (if available)", lambda: enroll_totp(users) if 'enroll_totp' in globals() else print("TOTP not available.")),
        '4': ("Forgot Password", lambda: forgot_password(users)),
        '5': ("Quit", lambda: sys.exit(0))
    }
    while True:
        print("\nSecure Login System")
        for k, (label, _) in menu.items():
            print(f" {k}. {label}")
        choice = input("Select option: ").strip()
        action = menu.get(choice)
        if action:
            try:
                action[1]()
            except Exception as e:
                if RECOVERY_DEBUG:
                    print("[DEBUG] menu action exception:", e)
                print("An error occurred.")
        else:
            print("Invalid choice.")

def handle_login(users: Dict[str, UserRecord]):
    """Wrapper to execute login followed by second factor and final welcome message."""
    username = login(users)
    if not username:
        return
    user = users.get(username)
    if not user:
        return
    if second_factor(username, user):
        print(f"Welcome, {username}! You are now authenticated with MFA.")

def enroll_totp(users: Dict[str, UserRecord]):
    """Enroll a user in TOTP MFA by generating and storing a new secret.

    Prompts for username, ensures existence & non-duplication, then prints provisioning URI
    which can be entered or converted to a QR code. Requires `pyotp`.
    """
    if not pyotp:
        print("pyotp not installed. Install with 'pip install pyotp' to use TOTP.")
        return
    username = input("Username to enroll TOTP: ").strip()
    user = users.get(username)
    if not user:
        print("User not found.")
        return
    if user.totp_secret:
        print("User already has TOTP enrolled.")
        return
    secret = pyotp.random_base32()
    user.totp_secret = secret
    save_users(users)
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=username, issuer_name="SecureLoginDemo")
    print("TOTP enrollment successful.")
    print(f"Secret (store securely): {secret}")
    print("Add to your authenticator app using this URI or its QR code:")
    print(uri)
    print("Next login will request your TOTP code instead of a one-time printed OTP.")

# ----------------------------- Self Test / Demo --------------------------------

def demo_flow():
    """Run a scripted non-interactive demonstration of password + OTP success path."""
    print("Running demo flow...")
    users = {}
    pwd = "StrongP@ssw0rd!"
    users['alice'] = UserRecord(username='alice', password_hash=hash_password(pwd))
    assert verify_password(pwd, users['alice'].password_hash)
    username = 'alice'
    otp_code = generate_otp(username)
    assert verify_otp(username, otp_code) is True
    print("Demo completed: Password + OTP verified.")

# ----------------------------- Entry Point -------------------------------------

def parse_args(argv=None):
    """Parse command-line arguments.

    Args:
        argv: Optional custom argument list (defaults to sys.argv when None)
    Returns:
        argparse.Namespace with parsed flags.
    """
    p = argparse.ArgumentParser(description="Secure Login System with Password Strength and OTP.")
    p.add_argument('--demo', action='store_true', help='Run a scripted demo flow and exit.')
    return p.parse_args(argv)


def main():
    """Program entry point: decides between demo and interactive modes."""
    args = parse_args()
    if args.demo:
        demo_flow()
        return
    interactive_main()

if __name__ == '__main__':
    main()
