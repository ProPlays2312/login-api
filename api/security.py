"""Security utilities: password validation, input sanitization, rate limiting, security headers, and security event logging."""

import re
import time
import logging
from collections import defaultdict
from functools import wraps
from flask import request, jsonify
from api.utils import safe_print

# ─── Security Logger ───────────────────────────────────────────────────────────
security_logger = logging.getLogger("vault_auth_security")
if not security_logger.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(logging.Formatter(
        "%(asctime)s [SECURITY] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S"
    ))
    security_logger.addHandler(_handler)
    security_logger.setLevel(logging.INFO)


def log_security_event(event_type, uid=None, ip=None, details=None):
    """Log a security-relevant event with automatic redaction of secrets."""
    try:
        client_ip = ip or (request.remote_addr if request else "unknown")
    except Exception:
        client_ip = ip or "unknown"

    safe_details = str(details or "")
    # Redact passwords, OTPs, tokens
    for pattern in [
        r'(?i)(password[\s:=]+)\S+',
        r'(?i)(otp[\s:=]+)\d+',
        r'(?i)(code[\s:=]+)\d{4,8}',
        r'(?i)(token[\s:=]+)[A-Za-z0-9_\-\.]{16,}',
        r'(?i)(secret[\s:=]+)\S+'
    ]:
        safe_details = re.sub(pattern, r'\1[REDACTED]', safe_details)

    security_logger.info(f"event={event_type} uid={uid or 'anonymous'} ip={client_ip} details={safe_details}")


# ─── In-Memory Rate Limiter ────────────────────────────────────────────────────
_rate_buckets = defaultdict(list)
_last_cleanup = 0.0


def _get_client_ip():
    try:
        xff = request.headers.get("X-Forwarded-For", "")
        if xff:
            # Client IP is the first non-empty component
            return xff.split(",")[0].strip()
        return request.remote_addr or "127.0.0.1"
    except Exception:
        return "127.0.0.1"


def rate_limit(max_requests=10, window_seconds=60, key_prefix="rl"):
    """Decorator to limit requests by client IP within a rolling time window."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            global _last_cleanup
            ip = _get_client_ip()
            bucket_key = f"{key_prefix}:{ip}"
            now = time.time()
            cutoff = now - window_seconds

            # Periodic global eviction of stale keys every 60 seconds to prevent unbounded memory growth
            if now - _last_cleanup > 60:
                _last_cleanup = now
                stale_keys = [k for k, timestamps in _rate_buckets.items() if not timestamps or max(timestamps) <= cutoff]
                for k in stale_keys:
                    _rate_buckets.pop(k, None)

            # Filter old requests in current bucket
            valid_requests = [t for t in _rate_buckets.get(bucket_key, []) if t > cutoff]
            _rate_buckets[bucket_key] = valid_requests

            if len(valid_requests) >= max_requests:
                oldest = valid_requests[0]
                retry_after = max(1, int(window_seconds - (now - oldest)))
                log_security_event("RATE_LIMIT_EXCEEDED", ip=ip, details=f"prefix={key_prefix} endpoint={request.path}")
                resp = jsonify({
                    "success": False,
                    "message": f"Too many requests. Please wait {retry_after} seconds before retrying.",
                    "retry_after": retry_after
                })
                resp.headers["Retry-After"] = str(retry_after)
                return resp, 429

            _rate_buckets[bucket_key].append(now)
            return f(*args, **kwargs)
        return decorated
    return decorator


# ─── Input Sanitization & Validation ──────────────────────────────────────────
_DANGEROUS_PATTERNS = re.compile(
    r"(<script|</script|javascript:|on\w+\s*=|<iframe|<object|<embed|data:text/html)",
    re.IGNORECASE
)

_COMMON_WEAK_PASSWORDS = {
    "password", "12345678", "123456789", "qwerty123", "admin123",
    "password123", "welcome1", "iloveyou", "abcdef123"
}


def sanitize_string(value, max_length=255):
    """Sanitize and validate a string against XSS patterns and length limits."""
    if value is None:
        return None
    value = str(value).strip()
    if len(value) > max_length:
        raise ValueError(f"Input exceeds maximum allowed length of {max_length} characters")
    if _DANGEROUS_PATTERNS.search(value):
        raise ValueError("Input contains disallowed or potentially malicious characters")
    return value


def validate_email(email):
    """Validate RFC 5321 compliant email format."""
    if not email or not isinstance(email, str):
        raise ValueError("Email is required")
    email = email.strip().lower()
    if len(email) > 254:
        raise ValueError("Email exceeds maximum length of 254 characters")
    pattern = r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$'
    if not re.match(pattern, email):
        raise ValueError("Invalid email format")
    if _DANGEROUS_PATTERNS.search(email):
        raise ValueError("Invalid characters in email")
    return email


def validate_username(username):
    """Validate username: 3-50 chars, alphanumeric + underscores, hyphens, and dots."""
    if not username or not isinstance(username, str):
        raise ValueError("Username is required")
    username = username.strip()
    if len(username) < 3:
        raise ValueError("Username must be at least 3 characters long")
    if len(username) > 50:
        raise ValueError("Username must not exceed 50 characters")
    if not re.match(r'^[a-zA-Z0-9_.\-]+$', username):
        raise ValueError("Username may only contain letters, numbers, underscores, dots, and hyphens")
    return username


def validate_password_strength(password):
    """
    Validate password policy and evaluate strength.
    Enforces minimum 8 characters and checks against empty or trivial weak passwords.
    Returns: (is_valid: bool, strength: str, errors: list[str])
    """
    if not password or not isinstance(password, str):
        return False, "Weak", ["Password cannot be empty."]

    errors = []
    if len(password) < 8:
        errors.append("Password must be at least 8 characters long.")

    if password.lower() in _COMMON_WEAK_PASSWORDS:
        errors.append("Password is too common and easily guessed.")

    if len(set(password)) < 4:
        errors.append("Password lacks variety of characters.")

    if errors:
        return False, "Weak", errors

    # Calculate strength rating
    score = 0
    if len(password) >= 10:
        score += 1
    if len(password) >= 14:
        score += 1
    if re.search(r'[A-Z]', password):
        score += 1
    if re.search(r'[a-z]', password):
        score += 1
    if re.search(r'\d', password):
        score += 1
    if re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]', password):
        score += 1

    if score >= 5:
        strength = "Strong"
    elif score >= 3:
        strength = "Medium"
    else:
        strength = "Weak"

    return True, strength, []


# ─── Security Headers ──────────────────────────────────────────────────────────
def add_security_headers(response):
    """Add defense-in-depth HTTP security headers to every response."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://unpkg.com; "
        "style-src 'self' 'unsafe-inline' https://unpkg.com; "
        "img-src 'self' data: https:; "
        "connect-src 'self' http://127.0.0.1:5000 http://localhost:5000 http://localhost:3000;"
    )
    # Remove Server fingerprinting
    response.headers.pop("Server", None)
    return response
