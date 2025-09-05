# Secure Login System 

## Overview
`secure_login.py` provides an educational example of a multi-factor authentication (MFA) flow in Python. It focuses on password strength validation, secure password storage, and a second factor using either TOTP (if available) or a fallback one-time code.

## Architecture Summary
- User store: JSON file (`users.json`) storing username, password hash, optional TOTP secret.
- Core modules used: `hashlib` (PBKDF2), `secrets` (cryptographic randomness), `re` (regex policy), `pyotp` (optional TOTP), `argparse` (CLI), `getpass` (hidden password input).
- MFA Strategy:
  1. Primary factor: Username + password.
  2. Secondary factor: Preferred TOTP (time-based rolling code). If no TOTP secret enrolled, fallback single-use OTP generated per login attempt.

## Data Model
```
UserRecord:
  username: str
  password_hash: str   # Format: pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>
  totp_secret: Optional[str]  # Base32 secret for TOTP generation if enrolled
```

## Password Handling
- Hash function: PBKDF2-HMAC-SHA256 with 130,000 iterations and 16-byte random salt.
- Stored format enables future algorithm migration by prefixing with algorithm and iteration count.
- Verification uses constant-time comparison (`secrets.compare_digest`).

## Password Policy
Enforced by a compiled regex and granular checks if regex fails:
- Minimum length: 8
- At least one uppercase letter A-Z
- At least one lowercase letter a-z
- At least one digit 0-9
- At least one special (non-alphanumeric) character

Validation function returns `(bool, message)` for user feedback.

## OTP (Fallback) Flow
- Generated via `secrets.choice` for each digit (length 6).
- Stored transiently in `_active_otps` with expiry (120s) and max attempts (3).
- On verification success or failure (attempts exhausted / expired) record is deleted.

## TOTP Flow
- Optional; requires `pyotp` package.
- Enrollment: generates Base32 secret, stores in user record, provides provisioning URI (issuer: `SecureLoginDemo`).
- Verification: Accepts codes valid in the current step with a small `valid_window=1` allowance for clock skew.
- If TOTP secret exists for a user, fallback OTP is bypassed.

## CLI Flow
1. Register: create username + strong password.
2. (Optional) Enroll TOTP: adds second factor secret.
3. Login: validate password -> choose second factor path (TOTP or fallback OTP) -> success or failure.
4. Demo mode (`--demo`): scripted demonstration without interaction.

## Functions (Key)
- `validate_password(pwd)`: Returns tuple `(ok, message)`.
- `hash_password(pwd)`: Returns full PBKDF2 parameterized hash string.
- `verify_password(pwd, stored)`: Validates candidate password.
- `generate_otp(username)`: Creates & stores ephemeral OTP record.
- `verify_otp(username, code)`: Validates user OTP, enforcing attempts & expiry.
- `second_factor(username, user)`: Branches to TOTP or fallback OTP.
- `enroll_totp(users)`: Adds a TOTP secret to an existing user (if `pyotp`).

## Security Considerations (Educational Simplifications)
| Aspect | Current Approach | Production Recommendation |
|--------|------------------|---------------------------|
| Password Hashing | PBKDF2-SHA256 130k iterations | Tune iterations, consider Argon2 | 
| User Store | JSON flat file | Database with access controls |
| OTP Delivery | Printed to console | SMS, Email, Push, or App |
| TOTP Secret Storage | Plain in JSON | Encrypt at rest / secrets manager |
| Rate Limiting | Basic attempt counters | Centralized throttling & lockouts |
| Logging | None | Structured security logs with redaction |
| Enumeration | Detailed feedback | Generic responses to hide which field failed |
| Transport | Assumes trusted local console | TLS + secure channels |

## Extensibility Ideas
- QR code generation for TOTP URI (`qrcode` + ASCII / image output).
- Add Argon2id hashing (via `argon2-cffi`).
- Add password breach checking (HIBP API with k-anonymity).
- Implement account lockout with exponential backoff and timestamp tracking.
- Integrate with SQLite (schema: users, auth_events, mfa_tokens).
- Add logging (`logging` module) with INFO (flow) + WARNING (security events).
- Add unit tests (sample previously provided) and GitHub Actions workflow.

## Demo Script Internals
`demo_flow()`:
1. Creates in-memory user with known strong password.
2. Verifies hash round-trip.
3. Generates and immediately verifies fallback OTP.

## Error Handling Strategy
- Broad exceptions in user load fall back to empty dict (simplified for class use).
- Functions return boolean success; calling flows decide messaging.
- TOTP gracefully skipped if dependency missing.

## Threat Modeling (High-Level)
| Threat | Mitigation in Demo | Gaps |
|--------|--------------------|------|
| Offline password cracking | Salt + PBKDF2 iterations | Stronger KDF (Argon2), secret pepper |
| Brute force login | Attempt counter | Persistent IP/username throttling |
| OTP replay | One-time + consumed | Could bind to session id |
| Code interception | N/A (console print) | Secure channel needed |
| TOTP secret theft | Stored in plain JSON | Encrypt, restrict FS permissions |

## Quick Usage Recap
```powershell
python .\secure_login.py        # interactive
python .\secure_login.py --demo # demo
```
Enroll TOTP after registering a user for stronger MFA.

## License / Usage
Intended for instructional use in an academic setting. Not production-hardened.
