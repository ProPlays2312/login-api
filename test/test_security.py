"""Comprehensive security test suite for VaultAuth SSO.

Covers:
- Password strength enforcement
- Input sanitization & XSS prevention
- Token expiry and cryptographic validation
- Protected endpoint authorization
- Role-Based Access Control (RBAC) & Privilege Escalation prevention
- IDOR (Insecure Direct Object Reference) prevention
- Session revocation enforcement
- OTP security (brute-force protection, single-use, non-exposure)
- HTTP security response headers
- Rate limiting protection
"""

import time
import pytest


# ─── Password Strength Validation ─────────────────────────────────────────────

class TestPasswordSecurity:
    def test_password_too_short_rejected(self):
        from api.security import validate_password_strength
        valid, strength, errors = validate_password_strength("Short1!")
        assert valid is False
        assert any("8 characters" in err for err in errors)

    def test_empty_password_rejected(self):
        from api.security import validate_password_strength
        valid, strength, errors = validate_password_strength("")
        assert valid is False
        assert any("empty" in err.lower() for err in errors)

    def test_common_weak_password_rejected(self):
        from api.security import validate_password_strength
        valid, strength, errors = validate_password_strength("password123")
        assert valid is False
        assert any("common" in err.lower() for err in errors)

    def test_lack_of_variety_rejected(self):
        from api.security import validate_password_strength
        valid, strength, errors = validate_password_strength("aaaaaaaa")
        assert valid is False

    def test_strong_password_accepted(self):
        from api.security import validate_password_strength
        valid, strength, errors = validate_password_strength("VaultAuth@2026!Sec")
        assert valid is True
        assert errors == []
        assert strength == "Strong"


# ─── Input Sanitization & Validation ──────────────────────────────────────────

class TestInputSanitization:
    def test_xss_script_tags_rejected(self):
        from api.security import sanitize_string
        with pytest.raises(ValueError):
            sanitize_string("<script>alert('xss')</script>")

    def test_javascript_protocol_rejected(self):
        from api.security import sanitize_string
        with pytest.raises(ValueError):
            sanitize_string("javascript:document.cookie")

    def test_iframe_injection_rejected(self):
        from api.security import sanitize_string
        with pytest.raises(ValueError):
            sanitize_string("<iframe src='evil.com'></iframe>")

    def test_valid_string_passed(self):
        from api.security import sanitize_string
        result = sanitize_string("CleanInput_2026")
        assert result == "CleanInput_2026"

    def test_string_exceeding_max_length_rejected(self):
        from api.security import sanitize_string
        with pytest.raises(ValueError):
            sanitize_string("A" * 300, max_length=255)

    def test_valid_email_passes(self):
        from api.security import validate_email
        assert validate_email("employee@vaultauth.io") == "employee@vaultauth.io"

    def test_invalid_email_missing_at_rejected(self):
        from api.security import validate_email
        with pytest.raises(ValueError):
            validate_email("invalidemail.com")

    def test_valid_username_passes(self):
        from api.security import validate_username
        assert validate_username("john_doe-2026") == "john_doe-2026"

    def test_username_too_short_rejected(self):
        from api.security import validate_username
        with pytest.raises(ValueError):
            validate_username("ab")

    def test_username_with_special_chars_rejected(self):
        from api.security import validate_username
        with pytest.raises(ValueError):
            validate_username("admin<script>")


# ─── Token Expiry & Session Invalidation ──────────────────────────────────────

class TestTokenAndSessionSecurity:
    def test_expired_token_rejected(self):
        from api.token import verify_token
        past_timestamp = int(time.time()) - 100
        expired_token = f"d41d8cd98f00b204e9800998ecf8427e.{past_timestamp}"
        assert verify_token(expired_token) is False

    def test_valid_token_accepted(self):
        from api.token import verify_token, session_token
        valid_token = session_token("testmd5hash")
        assert verify_token(valid_token) is True

    def test_malformed_token_rejected(self):
        from api.token import verify_token
        assert verify_token("not-a-valid-token") is False
        assert verify_token("") is False
        assert verify_token(None) is False

    def test_revoked_session_rejected_in_middleware(self, monkeypatch):
        """Ensure a session explicitly marked is_active=False cannot authenticate."""
        from api import auth_middleware
        # Mock active_sessions query returning session_active=False
        monkeypatch.setattr(
            auth_middleware,
            "execute_query",
            lambda q, p=None: [{"session_id": 1, "uid": 5, "session_active": False, "username": "alice", "is_active": True}]
        )
        user = auth_middleware.resolve_user_from_token("fake.token.123")
        assert user is None


# ─── Protected Routes Authorization ───────────────────────────────────────────

class TestRouteProtection:
    def test_dashboard_requires_auth(self, client):
        endpoints = [
            "/api/dashboard/overview",
            "/api/sessions",
            "/api/connected-apps",
            "/api/security/checklist",
            "/api/security/score",
            "/api/user/profile",
            "/api/user/role",
        ]
        for ep in endpoints:
            res = client.get(ep)
            assert res.status_code == 401

    def test_invalid_bearer_token_rejected(self, client):
        res = client.get("/api/sessions", headers={"Authorization": "Bearer invalid.token.value"})
        assert res.status_code == 401


# ─── Role-Based Access Control (RBAC) ─────────────────────────────────────────

class TestRBAC:
    def test_normal_user_rejected_from_admin_directory(self, client, monkeypatch):
        """A normal user (role=user) must be rejected with 403 Forbidden from admin endpoints."""
        from api.token import session_token
        token = session_token("userhash")

        # Mock authenticated as normal user
        monkeypatch.setattr(
            "api.auth_middleware.resolve_user_from_token",
            lambda t: {"uid": 10, "username": "employee", "email": "emp@vault.io", "is_active": True}
        )
        monkeypatch.setattr("api.rbac.get_user_role", lambda uid: "user")

        res = client.get("/api/admin/users", headers={"Authorization": f"Bearer {token}"})
        assert res.status_code == 403
        data = res.get_json()
        assert data.get("success") is False
        assert "Insufficient" in data.get("message", "")

    def test_normal_user_cannot_escalate_role(self, client, monkeypatch):
        """A normal user cannot change roles via the admin API."""
        from api.token import session_token
        token = session_token("userhash")

        monkeypatch.setattr(
            "api.auth_middleware.resolve_user_from_token",
            lambda t: {"uid": 10, "username": "employee", "email": "emp@vault.io", "is_active": True}
        )
        monkeypatch.setattr("api.rbac.get_user_role", lambda uid: "user")

        res = client.put(
            "/api/admin/users/10/role",
            json={"role": "admin"},
            headers={"Authorization": f"Bearer {token}"}
        )
        assert res.status_code == 403

    def test_admin_user_can_access_admin_directory(self, client, monkeypatch):
        """An admin user can access the admin directory."""
        from api.token import session_token
        token = session_token("adminhash")

        monkeypatch.setattr(
            "api.auth_middleware.resolve_user_from_token",
            lambda t: {"uid": 1, "username": "admin_user", "email": "admin@vault.io", "is_active": True}
        )
        monkeypatch.setattr("api.rbac.get_user_role", lambda uid: "admin")
        monkeypatch.setattr("main.get_user_role", lambda uid: "admin")
        monkeypatch.setattr("main.get_users", lambda q: [{"uid": 1, "username": "admin_user", "email": "admin@vault.io", "is_active": True}])

        res = client.get("/api/admin/users", headers={"Authorization": f"Bearer {token}"})
        assert res.status_code == 200
        data = res.get_json()
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["role"] == "admin"

    def test_user_can_inspect_own_role(self, client, monkeypatch):
        from api.token import session_token
        token = session_token("anyhash")

        monkeypatch.setattr(
            "api.auth_middleware.resolve_user_from_token",
            lambda t: {"uid": 5, "username": "alice", "email": "alice@vault.io", "is_active": True}
        )
        monkeypatch.setattr("api.rbac.get_user_role", lambda uid: "user")

        res = client.get("/api/user/role", headers={"Authorization": f"Bearer {token}"})
        assert res.status_code == 200
        assert res.get_json()["role"] == "user"


# ─── IDOR Protection ──────────────────────────────────────────────────────────

class TestIDORProtection:
    def test_user_cannot_revoke_foreign_session(self, client, monkeypatch):
        """A user cannot revoke a session owned by another user."""
        from api.token import session_token
        token = session_token("userahash")

        monkeypatch.setattr(
            "api.auth_middleware.resolve_user_from_token",
            lambda t: {"uid": 1, "username": "userA", "email": "a@vault.io", "is_active": True}
        )
        # Mock revoke_session to fail for target session belonging to user B
        monkeypatch.setattr(
            "main.revoke_session",
            lambda uid, sid: (False, "Session not found or already inactive")
        )

        res = client.delete("/api/sessions/sess_victim_session", headers={"Authorization": f"Bearer {token}"})
        assert res.status_code == 404
        assert res.get_json()["success"] is False


# ─── OTP Security Hardening ───────────────────────────────────────────────────

class TestOTPSecurity:
    def test_otp_code_never_exposed_in_send_response(self, client, monkeypatch):
        """The plaintext OTP must never be returned in the API response."""
        mock_otp_info = {
            "otp": "987654",
            "email": "user@example.com",
            "expires_in": 300,
            "cooldown": 60,
            "email_sent": True
        }
        monkeypatch.setattr("main.create_otp", lambda ident: (mock_otp_info, None))

        res = client.post("/api/otp/send", json={"identifier": "user@example.com"})
        assert res.status_code == 200
        data = res.get_json()
        assert "otp" not in data
        assert "987654" not in str(data)
        assert "email_masked" in data

    def test_otp_brute_force_lockout_message(self, client, monkeypatch):
        """After 5 failed attempts, OTP verification must reject with lockout message."""
        monkeypatch.setattr(
            "main.verify_otp",
            lambda ident, code: (None, "Maximum OTP attempts exceeded. Please request a new OTP.")
        )
        res = client.post("/api/otp/verify", json={"identifier": "alice", "otp": "000000"})
        assert res.status_code == 401
        assert "maximum" in res.get_json()["message"].lower()


# ─── HTTP Security Headers ────────────────────────────────────────────────────

class TestSecurityHeaders:
    def test_response_security_headers_enforced(self, client):
        res = client.get("/api/health")
        assert res.status_code == 200
        assert res.headers.get("X-Content-Type-Options") == "nosniff"
        assert res.headers.get("X-Frame-Options") == "DENY"
        assert res.headers.get("X-XSS-Protection") == "1; mode=block"
        assert "strict-origin" in res.headers.get("Referrer-Policy", "")
        assert "default-src 'self'" in res.headers.get("Content-Security-Policy", "")


# ─── Rate Limiting ────────────────────────────────────────────────────────────

class TestRateLimiting:
    def test_rate_limiter_blocks_excessive_requests(self, client):
        from api.security import rate_limit
        from flask import Flask, jsonify

        test_app = Flask("rl_test")

        @test_app.route("/test-rl")
        @rate_limit(max_requests=2, window_seconds=60, key_prefix="test_rl")
        def limited_endpoint():
            return jsonify({"status": "ok"}), 200

        with test_app.test_client() as test_client:
            # 1st request - OK
            res1 = test_client.get("/test-rl")
            assert res1.status_code == 200

            # 2nd request - OK
            res2 = test_client.get("/test-rl")
            assert res2.status_code == 200

            # 3rd request - Blocked with 429
            res3 = test_client.get("/test-rl")
            assert res3.status_code == 429
            data = res3.get_json()
            assert data["success"] is False
            assert "Too many requests" in data["message"]
            assert "Retry-After" in res3.headers
