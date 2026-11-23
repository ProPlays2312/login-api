"""Unit and integration tests for WebAuthn / FIDO2 Passkey authentication."""

import json
from unittest.mock import MagicMock
import pytest

from api.token import session_token
from api.webauthn_service import (
    create_webauthn_challenge,
    consume_webauthn_challenge,
    get_passkey_registration_options,
    get_passkey_authentication_options,
    get_user_passkeys,
    delete_user_passkey,
)


@pytest.fixture
def auth_headers(monkeypatch):
    """Fixture providing valid authentication headers for user with uid=1."""
    token = session_token("test-webauthn-token")
    monkeypatch.setattr(
        "api.auth_middleware.resolve_user_from_token",
        lambda tok: {"uid": 1, "username": "testuser", "email": "testuser@example.com", "role": "End User"}
    )
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


# ─── Challenge & Anti-Replay Tests ──────────────────────────────────────────

def test_webauthn_challenge_creation_and_consumption():
    """Verify challenge generation, byte formatting, and single-use consumption."""
    challenge_bytes, challenge_str = create_webauthn_challenge(uid=1, challenge_type="registration")
    assert len(challenge_bytes) == 32
    assert isinstance(challenge_str, str)
    assert len(challenge_str) > 20

    # First consumption: succeeds
    consumed = consume_webauthn_challenge(challenge_str, expected_type="registration", uid=1)
    assert consumed is not None
    assert consumed == challenge_bytes

    # Second consumption: fails (anti-replay guarantee)
    consumed_again = consume_webauthn_challenge(challenge_str, expected_type="registration", uid=1)
    assert consumed_again is None


def test_webauthn_challenge_uid_isolation():
    """Verify a challenge bound to user A cannot be consumed by user B."""
    _, challenge_str = create_webauthn_challenge(uid=10, challenge_type="registration")

    # Wrong UID fails
    consumed = consume_webauthn_challenge(challenge_str, expected_type="registration", uid=99)
    assert consumed is None

    # Correct UID succeeds
    consumed_correct = consume_webauthn_challenge(challenge_str, expected_type="registration", uid=10)
    assert consumed_correct is not None


# ─── Endpoint Tests: Registration ───────────────────────────────────────────

def test_register_options_unauthenticated(client):
    """Unauthenticated request to register options must be rejected with 401."""
    res = client.post("/api/webauthn/register/options")
    assert res.status_code == 401


def test_register_options_authenticated(client, auth_headers):
    """Authenticated request generates W3C PublicKeyCredentialCreationOptions."""
    res = client.post("/api/webauthn/register/options", headers=auth_headers)
    assert res.status_code == 200
    data = res.get_json()

    assert "challenge" in data
    assert "rp" in data
    assert data["rp"]["name"] == "VaultAuth SSO"
    assert "user" in data
    assert data["user"]["name"] == "testuser"
    assert "pubKeyCredParams" in data
    assert len(data["pubKeyCredParams"]) > 0


def test_register_verify_empty_body(client, auth_headers):
    """Empty payload returns 400."""
    res = client.post("/api/webauthn/register/verify", headers=auth_headers, json={})
    assert res.status_code == 400


def test_register_verify_invalid_challenge(client, auth_headers):
    """Bogus challenge payload returns 400."""
    bogus_payload = {
        "credential": {
            "id": "mock_cred_id",
            "rawId": "mock_cred_id",
            "type": "public-key",
            "response": {
                "clientDataJSON": "eyJjaGFsbGVuZ2UiOiAiaW52YWxpZCJ9",
                "attestationObject": "bW9jaw==",
            }
        },
        "deviceName": "MacBook Touch ID"
    }
    res = client.post("/api/webauthn/register/verify", headers=auth_headers, json=bogus_payload)
    assert res.status_code == 400
    assert res.get_json()["success"] is False


def test_register_verify_success_mocked(client, auth_headers, monkeypatch):
    """Successful registration stores credential and records audit log."""
    mock_cred_info = {
        "id": 1,
        "credential_id": "dGVzdC1jcmVkZW50aWFsLWlk",
        "device_name": "MacBook Touch ID",
        "created_at": "2026-11-23 10:00:00"
    }

    monkeypatch.setattr(
        "main.verify_and_save_passkey_registration",
        lambda user, credential_payload, device_name, client_ip, **kwargs: (
            True, "Passkey successfully registered!", mock_cred_info
        )
    )

    payload = {
        "credential": {
            "id": "dGVzdC1jcmVkZW50aWFsLWlkLWJ5dGVzLTEyMzQ1",
            "rawId": "dGVzdC1jcmVkZW50aWFsLWlkLWJ5dGVzLTEyMzQ1",
            "type": "public-key",
            "response": {
                "clientDataJSON": "mock_client_data",
                "attestationObject": "mock_attestation_object",
            }
        },
        "deviceName": "MacBook Touch ID"
    }

    res = client.post("/api/webauthn/register/verify", headers=auth_headers, json=payload)
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert "Passkey successfully registered" in data["message"]


# ─── Endpoint Tests: Login / Authentication ─────────────────────────────────

def test_login_options_without_identifier(client):
    """Login options request without identifier provides discoverable assertion challenge."""
    res = client.post("/api/webauthn/login/options", json={})
    assert res.status_code == 200
    data = res.get_json()

    assert "challenge" in data
    assert "rpId" in data
    assert data["rpId"] == "localhost"


def test_login_options_with_identifier(client, monkeypatch):
    """Login options with identifier populates user credentials in allowCredentials if found."""
    monkeypatch.setattr("opperation.get_users", lambda ident: [{"uid": 1, "username": "testuser"}])
    res = client.post("/api/webauthn/login/options", json={"identifier": "testuser"})
    assert res.status_code == 200
    data = res.get_json()
    assert "challenge" in data


def test_login_verify_unrecognized_passkey(client):
    """Attempting login with an unregistered credential ID is rejected."""
    payload = {
        "id": "unregistered-cred-id-xyz",
        "rawId": "unregistered-cred-id-xyz",
        "type": "public-key",
        "response": {
            "clientDataJSON": "eyJjaGFsbGVuZ2UiOiAidGVzdCJ9",
            "authenticatorData": "mock",
            "signature": "mock",
        }
    }
    res = client.post("/api/webauthn/login/verify", json=payload)
    assert res.status_code == 401
    assert "not recognized" in res.get_json()["message"]


def test_login_verify_success_mocked(client, monkeypatch):
    """Successful assertion verification issues session token, sets cookie, and returns user info."""
    mock_user = {
        "uid": 1,
        "username": "testuser",
        "email": "testuser@example.com",
        "full_name": "Test User",
        "is_active": True,
        "role": "End User"
    }

    monkeypatch.setattr(
        "main.verify_passkey_authentication",
        lambda *args, **kwargs: (True, "Passkey verified", mock_user)
    )
    monkeypatch.setattr("main.get_user_role", lambda uid: "End User")
    monkeypatch.setattr("main.record_login_activity", lambda *args, **kwargs: True)
    monkeypatch.setattr("main.create_user_session", lambda *args, **kwargs: True)
    monkeypatch.setattr("main.ensure_default_user_dashboard_data", lambda *args, **kwargs: True)

    payload = {
        "id": "test-valid-passkey-id",
        "rawId": "test-valid-passkey-id",
        "type": "public-key",
        "response": {
            "clientDataJSON": "mock_client_data",
            "authenticatorData": "mock_auth_data",
            "signature": "mock_signature",
        }
    }

    res = client.post("/api/webauthn/login/verify", json=payload)
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert "token" in data
    assert data["user"]["username"] == "testuser"
    assert "token=" in res.headers.get("Set-Cookie", "")


# ─── Endpoint Tests: Credential Management ───────────────────────────────────

def test_get_credentials_authenticated(client, auth_headers, monkeypatch):
    """Retrieve list of registered passkeys for the user."""
    mock_creds = [
        {
            "id": 1,
            "credential_id": "cid1234567890abcdef",
            "device_name": "MacBook Touch ID",
            "transports": "internal",
            "created_at": "2026-11-20 10:00:00",
            "last_used_at": "2026-11-22 14:00:00"
        }
    ]
    monkeypatch.setattr("api.webauthn_service.execute_query", lambda sql, params=None: mock_creds)

    res = client.get("/api/webauthn/credentials", headers=auth_headers)
    assert res.status_code == 200
    data = res.get_json()
    assert "credentials" in data
    assert len(data["credentials"]) == 1
    assert data["credentials"][0]["device_name"] == "MacBook Touch ID"


def test_delete_credential_idor_protection(client, auth_headers, monkeypatch):
    """Deleting a credential not owned by the authenticated user returns 400 / error."""
    # Mock lookup returns empty list (credential not found or belongs to another user)
    monkeypatch.setattr("api.webauthn_service.execute_query", lambda sql, params=None: [])

    res = client.delete("/api/webauthn/credentials/999", headers=auth_headers)
    assert res.status_code == 400
    assert "not found or access denied" in res.get_json()["message"]


def test_delete_credential_success(client, auth_headers, monkeypatch):
    """Deleting own credential succeeds."""
    mock_check = [{"id": 5, "device_name": "YubiKey 5C", "credential_id": "test_cid"}]

    def mock_query(sql, params=None):
        if "SELECT id, device_name, credential_id FROM webauthn_credentials" in sql:
            return mock_check
        return 1

    monkeypatch.setattr("api.webauthn_service.execute_query", mock_query)

    res = client.delete("/api/webauthn/credentials/5", headers=auth_headers)
    assert res.status_code == 200
    assert res.get_json()["success"] is True
    assert "Passkey successfully removed" in res.get_json()["message"]
