"""Unit tests for VaultAuth End User Dashboard APIs."""

import pytest
import json
from main import app
from api.token import generate_token, session_token


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


@pytest.fixture
def auth_headers(monkeypatch):
    """Provide valid mock authentication headers for testing."""
    mock_user = {
        "uid": 1,
        "username": "demo_user",
        "email": "demo@example.com",
        "full_name": "Demo User",
        "is_active": True
    }
    raw_token, _ = generate_token({"username": "demo_user", "uid": 1})
    token = session_token(raw_token)

    from api import auth_middleware
    monkeypatch.setattr(auth_middleware, "resolve_user_from_token", lambda tok: mock_user if tok == token else None)

    return {"Authorization": f"Bearer {token}"}, token


def test_dashboard_unauthenticated(client):
    """Verify that dashboard endpoints require authentication."""
    endpoints = [
        "/api/dashboard/overview",
        "/api/dashboard/login-activity",
        "/api/sessions",
        "/api/connected-apps",
        "/api/security/checklist",
        "/api/security/score",
        "/api/user/profile",
    ]
    for ep in endpoints:
        res = client.get(ep)
        assert res.status_code == 401
        data = res.get_json()
        assert data.get("success") is False or "Authentication required" in data.get("message", "")


def test_dashboard_overview_success(client, auth_headers, monkeypatch):
    """Verify /api/dashboard/overview returns all statistics."""
    headers, _ = auth_headers
    monkeypatch.setattr("main.ensure_default_user_dashboard_data", lambda uid, u: None)
    monkeypatch.setattr("main.get_dashboard_overview", lambda uid, tok: {
        "active_sessions": {"count": 2, "label": "2 devices", "description": "You're signed in on 2 devices"},
        "security_score": {"score": 92, "max_score": 100, "label": "92 / 100", "description": "Your account is well protected", "status": "ALL SYSTEMS NORMAL", "badge": "GOOD"},
        "connected_apps": {"count": 5, "label": "5 apps", "description": "Across your approved workspace"},
        "system_status": {"status": "ALL SYSTEMS NORMAL", "all_systems_normal": True}
    })

    res = client.get("/api/dashboard/overview", headers=headers)
    assert res.status_code == 200
    data = res.get_json()
    assert data["active_sessions"]["count"] == 2
    assert data["security_score"]["score"] == 92
    assert data["connected_apps"]["count"] == 5
    assert data["system_status"]["all_systems_normal"] is True


def test_dashboard_login_activity(client, auth_headers, monkeypatch):
    """Verify /api/dashboard/login-activity returns list of sign-ins."""
    headers, _ = auth_headers
    mock_activity = [
        {
            "id": 1,
            "device_name": 'MacBook Pro 16"',
            "device_type": "laptop",
            "browser": "Chrome 131",
            "location": "Bengaluru, India",
            "meta": "Chrome • Bengaluru, India",
            "ip_address": "103.21.58.xx",
            "status": "Success",
            "time_formatted": "Today, 9:42 AM"
        }
    ]
    monkeypatch.setattr("main.get_recent_login_activity", lambda uid, limit=10, filter_status=None: mock_activity)

    res = client.get("/api/dashboard/login-activity", headers=headers)
    assert res.status_code == 200
    data = res.get_json()
    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]["device_name"] == 'MacBook Pro 16"'
    assert data[0]["status"] == "Success"


def test_sessions_list_and_revoke(client, auth_headers, monkeypatch):
    """Verify sessions retrieval, individual revoke, and revoke others."""
    headers, _ = auth_headers
    mock_sessions = [
        {
            "id": 10,
            "session_id": "sess_abc123",
            "device_name": 'MacBook Pro 16"',
            "browser": "Chrome",
            "is_current": True
        },
        {
            "id": 11,
            "session_id": "sess_def456",
            "device_name": "Samsung Galaxy S25 Ultra",
            "browser": "VaultAuth mobile",
            "is_current": False
        }
    ]
    monkeypatch.setattr("main.get_active_sessions", lambda uid, tok: mock_sessions)
    monkeypatch.setattr("main.revoke_session", lambda uid, sid: (True, "Session revoked successfully") if sid == "sess_def456" else (False, "Session not found"))
    monkeypatch.setattr("main.revoke_other_sessions", lambda uid, tok: (True, "Revoked 1 other session(s)"))

    # 1. Get sessions
    res = client.get("/api/sessions", headers=headers)
    assert res.status_code == 200
    assert len(res.get_json()) == 2

    # 2. Revoke a session
    res = client.delete("/api/sessions/sess_def456", headers=headers)
    assert res.status_code == 200
    assert res.get_json()["success"] is True

    # 3. Revoke not found session
    res = client.delete("/api/sessions/nonexistent", headers=headers)
    assert res.status_code == 404
    assert res.get_json()["success"] is False

    # 4. Revoke other sessions
    res = client.post("/api/sessions/revoke-others", headers=headers)
    assert res.status_code == 200
    assert "Revoked" in res.get_json()["message"]


def test_connected_apps_and_disconnect(client, auth_headers, monkeypatch):
    """Verify connected apps list and disconnection."""
    headers, _ = auth_headers
    mock_apps = [
        {
            "id": 1,
            "app_key": "google",
            "app_name": "Google Workspace",
            "app_desc": "Email, Calendar, Drive",
            "permissions": ["Read email", "Calendar access"],
            "status": "Active"
        }
    ]
    monkeypatch.setattr("main.ensure_default_user_dashboard_data", lambda uid, u: None)
    monkeypatch.setattr("main.get_connected_applications", lambda uid: mock_apps)
    monkeypatch.setattr("main.disconnect_application", lambda uid, app_id: (True, "Application access revoked") if app_id == 1 else (False, "App not found"))

    res = client.get("/api/connected-apps", headers=headers)
    assert res.status_code == 200
    assert len(res.get_json()) == 1

    res = client.delete("/api/connected-apps/1", headers=headers)
    assert res.status_code == 200
    assert res.get_json()["success"] is True

    res = client.delete("/api/connected-apps/999", headers=headers)
    assert res.status_code == 404


def test_security_checklist_and_score(client, auth_headers, monkeypatch):
    """Verify checklist and score calculations."""
    headers, _ = auth_headers
    monkeypatch.setattr("main.ensure_default_user_dashboard_data", lambda uid, u: None)
    monkeypatch.setattr("main.get_security_checklist", lambda uid: {
        "badge": "GOOD",
        "items": [
            {"key": "mfa", "title": "Multi-factor authentication", "enabled": True},
            {"key": "recovery_email", "title": "Recovery email", "enabled": True},
            {"key": "password_strength", "title": "Password strength", "enabled": True}
        ]
    })
    monkeypatch.setattr("main.calculate_security_score", lambda uid: {
        "score": 92,
        "max_score": 100,
        "status": "ALL SYSTEMS NORMAL",
        "badge": "GOOD"
    })

    res = client.get("/api/security/checklist", headers=headers)
    assert res.status_code == 200
    assert res.get_json()["badge"] == "GOOD"

    res = client.get("/api/security/score", headers=headers)
    assert res.status_code == 200
    assert res.get_json()["score"] == 92


def test_user_profile_and_security_update(client, auth_headers, monkeypatch):
    """Verify profile retrieval and security settings updates."""
    headers, _ = auth_headers
    monkeypatch.setattr("main.ensure_default_user_dashboard_data", lambda uid, u: None)
    monkeypatch.setattr("main.get_user_profile", lambda uid: {
        "uid": 1,
        "username": "alex",
        "email": "alex.morgan@company.com",
        "full_name": "Alex Morgan",
        "role": "End user"
    })
    monkeypatch.setattr("main.update_security_settings", lambda uid, data: (True, "Updated successfully"))

    res = client.get("/api/user/profile", headers=headers)
    assert res.status_code == 200
    assert res.get_json()["full_name"] == "Alex Morgan"

    res = client.put("/api/security/settings", headers=headers, json={"recovery_email": "new@backup.com"})
    assert res.status_code == 200
    assert res.get_json()["success"] is True
