# Secure Login System (Python)

Unified documentation combining quick start and in-depth technical design.

## Table of Contents
1. Overview & Objectives
2. Features
	- Dependencies & Installation
3. Quick Start (Running & Menu)
4. MFA Principle
5. Password Policy
6. Architecture Summary
7. Data Model
8. Password Handling
9. OTP (Fallback) Flow
10. TOTP Flow
11. CLI Flow
12. Key Functions
13. Security Considerations / Gaps
14. Threat Modeling (High-Level)
15. Extensibility Ideas
16. Demo Script Internals
17. Error Handling Strategy
18. Quick Usage Recap

---
## 1. Overview & Objectives
Educational secure authentication flow demonstrating Multi-Factor Authentication (MFA) concepts:
1. Password strength validation with regular expressions.
2. Password hashing using salted PBKDF2-HMAC-SHA256 (never store plaintext).
3. Two second-factor options:
	 - Time-based One-Time Password (TOTP) via authenticator app (preferred, if `pyotp` installed).
	 - Fallback randomly generated 6-digit OTP (simulated delivery by printing to console).

## 2. Features
- Strong password policy (min length, upper, lower, digit, special char) with detailed feedback.
- Secure password hashing (pbkdf2_sha256 with 130k iterations).
- TOTP enrollment & verification (RFC 6238) if `pyotp` present.
- Fallback 6-digit cryptographically secure OTP (expires in 2 minutes, 3 attempts max) when TOTP not enrolled.
- Rate-limited login attempts & OTP attempt limits.
- In-memory + JSON file user storage (simple persistence demo).

### Dependencies & Installation
The core script works with only the Python standard library; TOTP is optional.

Required:
- Python 3.10+ (tested on 3.13)

Optional (enables extra capabilities):
- `pyotp` – TOTP second factor (recommended)

Development / Extension (only if you implement those enhancements):
- `pytest` – run/create tests
- `qrcode` – generate QR code for TOTP enrollment
- `argon2-cffi` – Argon2id password hashing alternative
- A local breach list file or API client (if adding password breach checks)

#### Quick Install (PowerShell)
```powershell
# (Optional) create & activate virtual environment
python -m venv .venv
./.venv/Scripts/Activate.ps1

# Install required/optional packages
pip install pyotp

# (Optional) for testing & extensions
pip install pytest qrcode argon2-cffi
```

If you prefer pinning, create/edit `requirements.txt` and run:
```powershell
pip install -r requirements.txt
```

## 3. Quick Start (Running & Menu)
File overview:
- `secure_login.py` – main application script.
- `users.json` – created automatically after first registration (stores hashed credentials only).

Interactive mode (PowerShell examples shown):
```powershell
python .\secure_login.py
```
Scripted demo (non-interactive):
```powershell
python .\secure_login.py --demo
```
Menu options:
1. Register
2. Login
3. Enroll TOTP (adds an app-based second factor if `pyotp` installed; otherwise notifies you)
4. Quit

## 4. MFA Principle
- Something you KNOW: username + password
- Something you HAVE: authenticator app generating TOTP OR transient fallback OTP (printed)

## 5. Password Policy
- Minimum length: 8
- At least 1 uppercase letter
- At least 1 lowercase letter
- At least 1 digit
- At least 1 special character

## 6. Architecture Summary
- User store: JSON file (`users.json`) with username, password hash, optional TOTP secret.
- Core modules: `hashlib`, `secrets`, `re`, `pyotp` (optional), `argparse`, `getpass`.
- MFA Strategy: Password -> (TOTP if enrolled else fallback one-time code).

## 7. Data Model
```
UserRecord:
	username: str
	password_hash: str   # pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>
	totp_secret: Optional[str]
```

## 8. Password Handling
- PBKDF2-HMAC-SHA256, 130k iterations, 16-byte random salt.
- Storable string encodes algorithm + iteration count for migration.
- Constant-time comparison via `secrets.compare_digest`.

## 9. OTP (Fallback) Flow
- 6-digit random numeric code per login attempt.
- Stored transiently with expiry (120s) + attempt cap (3).
- Consumed and deleted on success or exhaustion/expiry.

## 10. TOTP Flow
- Enrollment generates Base32 secret and provisioning URI (`SecureLoginDemo`).
- Verification accepts current 30s time-step (with slight skew window).
- Supersedes fallback OTP when secret present.

## 11. CLI Flow
1. Register user & strong password.
2. (Optional) Enroll TOTP.
3. Login -> password check -> second factor path -> success/failure.
4. `--demo` runs scripted showcase.

## 12. Key Functions
- `validate_password(pwd)` -> (ok, message)
- `hash_password(pwd)` / `verify_password(pwd, stored)`
- `generate_otp(username)` / `verify_otp(username, code)`
- `second_factor(username, user)` selects TOTP vs fallback
- `enroll_totp(users)` handles TOTP enrollment

## 13. Security Considerations / Gaps
| Aspect | Current | Production Recommendation |
|--------|---------|---------------------------|
| Password Hashing | PBKDF2-SHA256 130k | Tune iterations; consider Argon2id |
| User Store | JSON file | RDBMS with access controls |
| OTP Delivery | Console print | Secure channel (SMS/Email/Push/App) |
| TOTP Secret | Plain in JSON | Encrypt at rest / secret manager |
| Rate Limiting | Basic counters | Central throttling & lockouts |
| Logging | None | Structured, confidentiality-aware logs |
| Enumeration | Detailed feedback | Uniform generic responses |
| Transport | Local console assumed | TLS + hardened endpoints |

## 14. Threat Modeling (High-Level)
| Threat | Mitigation | Gap |
|--------|-----------|-----|
| Offline hash cracking | Salt + PBKDF2 | Stronger KDF / pepper |
| Brute force login | Attempt count | Persistent lockout/backoff |
| OTP replay | One-time & consumed | Bind to session ID |
| Code interception | N/A (demo) | Secure delivery channel |
| TOTP secret theft | Minimal FS controls | Encryption + permissions |

## 15. Extensibility Ideas
- Replace console OTP with real email/SMS gateway.
- Add account lockouts or exponential backoff.
- QR code for TOTP (`qrcode` library) output.
- Argon2id hashing alternative.
- Breached password checking (local list or HIBP k-anonymity).
- Structured logging & audit trail.
- Database integration (SQLite/Postgres) & migration scripts.
- CI pipeline + tests.

## 16. Demo Script Internals
`demo_flow()`:
1. Creates user with known strong password.
2. Verifies hash round-trip.
3. Generates & verifies fallback OTP.

## 17. Error Handling Strategy
- Safe fallback to empty user store if load fails.
- Boolean returns for clarity; caller prints messages.
- Graceful no-TOTP path if dependency absent.

## 18. Quick Usage Recap
```powershell
python .\secure_login.py        # interactive
python .\secure_login.py --demo # demo
```
Enroll TOTP after registering for stronger MFA.