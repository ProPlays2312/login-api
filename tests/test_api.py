def test_get_users_success(client, monkeypatch):
    mock_users = [{"uid": 1, "username": "alice", "email": "alice@example.com"}]
    monkeypatch.setattr("main.get_users", lambda uid: mock_users)

    response = client.get("/api/users")
    assert response.status_code == 200
    assert response.get_json() == mock_users


def test_get_user_by_id_found(client, monkeypatch):
    mock_user = [{"uid": 1, "username": "alice", "email": "alice@example.com"}]
    monkeypatch.setattr("main.get_users", lambda uid: mock_user)

    response = client.get("/api/users/1")
    assert response.status_code == 200
    assert response.get_json() == mock_user


def test_get_user_by_id_not_found(client, monkeypatch):
    monkeypatch.setattr("main.get_users", lambda uid: None)

    response = client.get("/api/users/999")
    assert response.status_code == 404
    assert response.get_json()["message"] == "Error: User not found"


def test_register_missing_data(client):
    response = client.post("/api/register", data="null", content_type="application/json")
    assert response.status_code == 400
    assert response.get_json()["message"] == "Data is null"


def test_register_success(client, monkeypatch):
    monkeypatch.setattr("main.register", lambda data: True)

    payload = {"username": "bob", "password": "secure123", "email": "bob@example.com", "uid": 2}
    response = client.post("/api/register", json=payload)
    assert response.status_code == 200
    assert response.get_json() is True


def test_login_missing_data(client):
    response = client.post("/api/login", data="null", content_type="application/json")
    assert response.status_code == 400
    assert response.get_json()["message"] == "Data is null"


def test_login_invalid_credentials(client, monkeypatch):
    monkeypatch.setattr("main.auth_user", lambda login, pwd: None)

    response = client.post("/api/login", json={"login": "nobody", "password": "wrongpassword"})
    assert response.status_code == 404
    assert response.get_json()["message"] == "User not found"


def test_login_success(client, monkeypatch):
    mock_user = {"uid": 1, "username": "alice", "email": "alice@example.com"}
    monkeypatch.setattr("main.auth_user", lambda login, pwd: mock_user)

    response = client.post("/api/login", json={"login": "alice", "password": "secretpassword"})
    assert response.status_code == 200
    data = response.get_json()
    assert data["message"] == "Login successful"
    assert "token" in data
    assert "." in data["token"]


def test_openapi_spec(client):
    response = client.get("/openapi.json")
    assert response.status_code == 200
    data = response.get_json()
    assert data["openapi"] == "3.0.3"
    assert data["info"]["title"] == "Vault Auth API"
    assert "/api/login" in data["paths"]
    assert "/api/register" in data["paths"]
    assert "/api/users" in data["paths"]


def test_swagger_ui_docs(client):
    response = client.get("/docs")
    assert response.status_code == 200
    assert "SwaggerUIBundle" in response.get_data(as_text=True)


def test_verify_token_success(client):
    from api.token import session_token
    token = session_token("testmd5hash")

    # Via Authorization Header
    res = client.get("/api/verify", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    assert res.get_json()["valid"] is True

    # Via JSON body
    res_post = client.post("/api/verify", json={"token": token})
    assert res_post.status_code == 200
    assert res_post.get_json()["valid"] is True


def test_verify_token_failure(client):
    # Missing token
    res = client.get("/api/verify")
    assert res.status_code == 401
    assert res.get_json()["valid"] is False

    # Expired / malformed token
    res_bad = client.get("/api/verify", headers={"Authorization": "Bearer bad.100"})
    assert res_bad.status_code == 401
    assert res_bad.get_json()["valid"] is False


def test_logout_success(client):
    with client.session_transaction() as sess:
        sess["token"] = "valid.token"

    res = client.post("/api/logout")
    assert res.status_code == 200
    assert res.get_json()["message"] == "Logout successful"


def test_health_check(client):
    res = client.get("/api/health")
    assert res.status_code == 200
    assert res.get_json()["status"] == "ok"


def test_send_otp_success(client, monkeypatch):
    mock_otp_info = {
        "otp": "654321",
        "email": "alice@vault.io",
        "expires_in": 300
    }
    monkeypatch.setattr("main.create_otp", lambda ident: (mock_otp_info, None))

    res = client.post("/api/otp/send", json={"identifier": "alice"})
    assert res.status_code == 200
    data = res.get_json()
    assert "OTP sent" in data["message"]
    assert data["identifier"] == "alice"
    assert "otp" not in data


def test_send_otp_email_delivery_failed_500(client, monkeypatch):
    mock_otp_info = {
        "otp": "654321",
        "email": "alice@vault.io",
        "expires_in": 300,
        "email_sent": False,
        "email_err": "Gmail credentials not configured"
    }
    monkeypatch.setattr("main.create_otp", lambda ident: (mock_otp_info, None))

    res = client.post("/api/otp/send", json={"identifier": "alice"})
    assert res.status_code == 500
    data = res.get_json()
    assert "Email delivery failed" in data["message"]


def test_send_otp_not_found(client, monkeypatch):
    monkeypatch.setattr("main.create_otp", lambda ident: (None, "User not found"))
    res = client.post("/api/otp/send", json={"identifier": "unknown"})
    assert res.status_code == 404
    assert res.get_json()["message"] == "User not found"


def test_verify_otp_endpoint_success(client, monkeypatch):
    mock_user = {"uid": 2, "username": "alice", "email": "alice@vault.io"}
    monkeypatch.setattr("main.verify_otp", lambda ident, code: (mock_user, None))

    res = client.post("/api/otp/verify", json={"identifier": "alice", "otp": "654321"})
    assert res.status_code == 200
    data = res.get_json()
    assert data["message"] == "OTP login successful"
    assert "token" in data
    assert data["user"]["username"] == "alice"


def test_verify_otp_endpoint_invalid(client, monkeypatch):
    monkeypatch.setattr("main.verify_otp", lambda ident, code: (None, "Invalid or expired OTP"))
    res = client.post("/api/otp/verify", json={"identifier": "alice", "otp": "000000"})
    assert res.status_code == 401
    assert res.get_json()["message"] == "Invalid or expired OTP"


def test_send_otp_endpoint_cooldown_429(client, monkeypatch):
    monkeypatch.setattr(
        "main.create_otp",
        lambda ident: ({"cooldown_remaining": 45}, "Please wait 45 seconds before requesting a new OTP.")
    )
    res = client.post("/api/otp/send", json={"identifier": "alice"})
    assert res.status_code == 429
    data = res.get_json()
    assert data["retry_after"] == 45
    assert "Please wait 45 seconds" in data["message"]


def test_send_otp_endpoint_deactivated_403(client, monkeypatch):
    monkeypatch.setattr("main.create_otp", lambda ident: (None, "Account is deactivated"))
    res = client.post("/api/otp/send", json={"identifier": "deactivated_user"})
    assert res.status_code == 403
    assert "deactivated" in res.get_json()["message"]


def test_verify_otp_endpoint_deactivated_403(client, monkeypatch):
    monkeypatch.setattr("main.verify_otp", lambda ident, code: (None, "Account is deactivated"))
    res = client.post("/api/otp/verify", json={"identifier": "deactivated_user", "otp": "123456"})
    assert res.status_code == 403
    assert "deactivated" in res.get_json()["message"]
