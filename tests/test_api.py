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
