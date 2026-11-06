def test_get_users_success(client, monkeypatch):
    mock_users = [{"uid": 1, "username": "alice", "email": "alice@example.com"}]
    monkeypatch.setattr("main.get_users", lambda uid: mock_users)
    monkeypatch.setattr("main.verify_token", lambda token, data: True)
    with client.session_transaction() as session:
        session["token"] = "0" * 64 + ".9999999999"
        session["username"] = "alice"
        session["uid"] = 1

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


def test_register_validation_error_is_client_error(client, monkeypatch):
    monkeypatch.setattr(
        "main.register",
        lambda data: (_ for _ in ()).throw(
            ValueError("username, password, and email are required")
        ),
    )

    response = client.post("/api/register", json={})
    assert response.status_code == 400
    assert response.get_json()["message"] == (
        "username, password, and email are required"
    )


def test_internal_errors_do_not_leak_details(client, monkeypatch):
    monkeypatch.setattr("main.verify_token", lambda token, data: True)
    with client.session_transaction() as session:
        session["token"] = "0" * 64 + ".9999999999"
        session["username"] = "alice"
        session["uid"] = 1
    monkeypatch.setattr(
        "main.get_users",
        lambda uid: (_ for _ in ()).throw(
            RuntimeError("database password should not be exposed")
        ),
    )

    response = client.get("/api/users")
    assert response.status_code == 500
    assert response.get_json() == {"message": "Internal server error"}


def test_users_requires_authentication(client):
    response = client.get("/api/users")
    assert response.status_code == 401


def test_login_stores_verified_user_session(client, monkeypatch):
    monkeypatch.setattr(
        "main.auth_user",
        lambda login, password: {"uid": 1, "username": "alice"},
    )
    monkeypatch.setattr("main.generate_token", lambda data: ("a" * 64, "today"))

    response = client.post(
        "/api/login",
        json={"login": "alice", "password": "password"},
    )

    assert response.status_code == 200
    with client.session_transaction() as session:
        assert session["username"] == "alice"
        assert session["uid"] == 1
