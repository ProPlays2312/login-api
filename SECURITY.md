# VaultAuth SSO — Security Documentation & Specifications

**Project:** VaultAuth SSO — Identity and Access Management (IAM) Prototype  
**Author:** Senior Cybersecurity Engineer & Backend Security Developer  
**Status:** Implemented & Verified with 86/86 Passing Automated Tests  
**Version:** 1.1.0 (Security Hardened)  

---

## 1. Overview & Security Architecture

VaultAuth SSO is an Identity and Access Management (IAM) prototype built on Python/Flask and PostgreSQL, designed to deliver centralized authentication, time-based OTP two-factor verification, and an active end-user session dashboard.

```
       +-----------------------+
       |   End User Browser    |
       +-----------+-----------+
                   |
     HTTPS / Bearer Auth / JSON
                   |
                   v
+------------------+-------------------+
|            Flask API Gateway         |
|  - Content-Security-Policy & Headers |
|  - Rate Limiter (IP/Endpoint)        |
|  - Input Validation & Sanitization   |
|  - RBAC Authorization Decorators     |
+------------------+-------------------+
                   |
         +---------+---------+
         |                   |
         v                   v
+-----------------+   +------------------+
| Primary Auth    |   | Plunk Mailer     |
| (Werkzeug Hash) |   | (Encrypted OTP)  |
+--------+--------+   +--------+---------+
         |                     |
         v                     v
+------------------+-------------------+
|         PostgreSQL Database          |
|  - users (roles, hashed passwords)   |
|  - otps (hashed OTP, max 5 attempts) |
|  - active_sessions (revocation flag) |
|  - login_activity (audit trail)      |
+--------------------------------------+
```

---

## 2. Implemented Security Controls

### A. Password Security
- **Secure Hashing:** Werkzeug PBKDF2 with SHA-256 (`generate_password_hash` and `check_password_hash`).
- **Zero Plaintext Storage:** Passwords are never stored in plaintext. Legacy plaintext passwords encountered during authentication are automatically upgraded and hashed on the fly.
- **Password Policy:** Minimum length of 8 characters enforced at registration.
- **Complexity Assessment:** Password strength validator (`validate_password_strength`) evaluates character variety, rejecting common dictionary passwords (`password`, `12345678`, `admin123`).
- **Non-Exposure:** Passwords and password hashes are stripped from all API outputs and excluded from logs.

### B. Authentication & Session Security
- **Session Tokens:** Time-bounded session tokens (`token_hash.expiration_timestamp`).
- **Session Tracking:** Active sessions stored in `active_sessions` with device fingerprinting, IP masking, and timestamp tracking.
- **Revocation Enforcement:** Inactive or revoked sessions (`is_active = FALSE`) are rejected immediately by authentication middleware, preventing token reuse after revocation.
- **Authoritative Invalidation on Logout:** `/api/logout` sets `is_active = FALSE` on the session in the database, invalidating the token across all dashboard requests.
- **IDOR Protection:** Session revocation (`DELETE /api/sessions/<id>`) and app disconnection (`DELETE /api/connected-apps/<id>`) verify user ownership (`WHERE uid = %s`), preventing cross-user manipulation.

### C. OTP (2FA) Security
- **Cryptographic Generation:** Generated via Python's `secrets` module (`secrets.randbelow(900000) + 100000`) for high-entropy 6-digit codes.
- **Hashed Database Storage:** OTPs are hashed using SHA-256 with user salt (`hashlib.sha256(f"{uid}:{otp_code}".encode()).hexdigest()`).
- **Brute-Force Lockout:** Maximum of 5 failed verification attempts per active OTP. After 5 incorrect attempts, verification is locked out and the user must request a new OTP.
- **Strict Expiration:** Valid for exactly 5 minutes (300 seconds).
- **Single-Use Enforcement:** Marked `used = TRUE` immediately upon first successful verification. Replay attacks are rejected.
- **Resend Cooldown:** 60-second cooldown between consecutive OTP requests.
- **Rate Limiting:** Maximum 5 OTP requests per 15-minute window.
- **Non-Exposure:** Plaintext OTP codes are never returned in HTTP responses; email targets are masked (e.g. `a********4@gmail.com`).

### D. Role-Based Access Control (RBAC)
- **Roles:**
  - `user`: Standard End User with access to their own dashboard, sessions, and connected apps.
  - `admin`: Enterprise Admin with access to employee directory management and role modifications.
- **Backend Enforcement:** Reusable Flask decorators `@require_role(*roles)` and `@require_admin` inspect database roles, rejecting non-admin users with `403 Forbidden`.
- **Privilege Escalation Prevention:** Normal users cannot modify their own or other users' roles. Role modifications require an authenticated admin session via `PUT /api/admin/users/<uid>/role`.

### E. API Security & Defense-in-Depth
- **HTTP Security Headers:**
  - `X-Content-Type-Options: nosniff` (MIME sniffing prevention)
  - `X-Frame-Options: DENY` (Clickjacking prevention)
  - `X-XSS-Protection: 1; mode=block`
  - `Referrer-Policy: strict-origin-when-cross-origin`
  - `Permissions-Policy: geolocation=(), microphone=(), camera=()`
  - `Content-Security-Policy`: Restricts scripts and styles to approved origins.
- **Rate Limiting:**
  - `/api/login`: 15 requests / 60 seconds
  - `/api/register`: 10 requests / 60 seconds
  - `/api/otp/send`: 10 requests / 60 seconds
  - `/api/otp/verify`: 15 requests / 60 seconds
- **Request Size Limiting:** `MAX_CONTENT_LENGTH = 1MB` to mitigate payload flooding / DoS attacks.
- **Parameterized SQL Queries:** All database interactions use `%s` placeholder parameterization via `psycopg2`, preventing SQL injection.
- **Information Leakage Prevention:** Internal exceptions and stack traces are logged server-side and sanitized in API error responses.

### F. Security Logging & Monitoring
- Structured logging via `log_security_event` for:
  - `LOGIN_SUCCESS` / `LOGIN_FAILED`
  - `REGISTRATION_SUCCESS` / `REGISTRATION_REJECTED`
  - `OTP_SENT_SUCCESS` / `OTP_DELIVERY_FAILED`
  - `OTP_VERIFY_SUCCESS` / `OTP_VERIFY_FAILED`
  - `LOGOUT_SESSION_INVALIDATED`
  - `UNAUTHORIZED_ACCESS_ATTEMPT`
  - `ADMIN_DIRECTORY_ACCESSED`
  - `ADMIN_ROLE_CHANGE`
- Automatic redaction of sensitive credentials (passwords, tokens, OTPs) from logs.

---

## 3. API Endpoints Specification

### Public / Authentication Endpoints
| Method | Endpoint | Description | Rate Limit |
|---|---|---|---|
| `GET` | `/api/health` | Service health check | None |
| `POST` | `/api/register` | Register new employee account | 10 / min |
| `POST` | `/api/login` | Primary credentials login | 15 / min |
| `POST` | `/api/otp/send` | Request email OTP for MFA | 10 / min |
| `POST` | `/api/otp/verify` | Verify OTP code and issue session token | 15 / min |
| `GET/POST` | `/api/verify` | Verify session token validity | None |
| `POST` | `/api/logout` | Revoke active session and logout | None |

### Protected User Dashboard Endpoints (`@require_auth`)
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/dashboard/overview` | Dynamic statistics (sessions, score, apps) |
| `GET` | `/api/dashboard/login-activity` | Filtered login activity audit logs |
| `GET` | `/api/sessions` | List all active device sessions |
| `DELETE` | `/api/sessions/<session_id>` | Revoke a specific active session |
| `POST` | `/api/sessions/revoke-others` | Revoke all sessions except current |
| `GET` | `/api/connected-apps` | List approved third-party workspace apps |
| `DELETE` | `/api/connected-apps/<app_id>` | Disconnect third-party application |
| `GET` | `/api/security/checklist` | MFA, recovery email, password strength check |
| `GET` | `/api/security/score` | Dynamic 0-100 account security rating |
| `PUT` | `/api/security/settings` | Update security & recovery settings |
| `GET` | `/api/user/profile` | Authenticated user profile data |
| `GET` | `/api/user/role` | Current user's assigned RBAC role |

### Enterprise Admin Endpoints (`@require_auth`, `@require_admin`)
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/admin/users` | List all employee accounts with roles |
| `PUT` | `/api/admin/users/<uid>/role` | Assign user role (`user` or `admin`) |

---

## 4. Running the Application & Security Tests

### Running the Backend Server
```bash
cd /Users/amitojsingharora/Desktop/vault-auth-backend
source .venv/bin/activate
python3 main.py
```
Server runs at `http://127.0.0.1:5000`.

### Running All Automated Security Tests
```bash
cd /Users/amitojsingharora/Desktop/vault-auth-backend
source .venv/bin/activate
pytest -v
```

### Running the Dedicated Security Test Suite
```bash
pytest test/test_security.py -v
```

---

## 5. Known Prototype Limitations & Production Recommendations

1. **Token Cryptography:** The current prototype uses token format `<hash>.<timestamp>`. For production deployments, transition to signed JWTs (e.g. Ed25519 or HMAC-SHA256) or opaque Redis session identifiers.
2. **Rate Limiting Storage:** In-memory rate limiting is node-local and resets upon restart. Production clusters should back rate limiting with Redis (`flask-limiter` + Redis).
3. **Transport Security:** Enforce HTTPS/HSTS at the reverse proxy (Nginx / Cloudflare) to ensure tokens and credentials are never transmitted over unencrypted HTTP.
4. **Token Storage on Client:** In browser environments, store authentication tokens in `HttpOnly; Secure; SameSite=Strict` cookies to eliminate token theft via Cross-Site Scripting (XSS).
