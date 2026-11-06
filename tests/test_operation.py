from opperation import auth_user, get_users, register


def test_auth_user_uses_parameterized_query(monkeypatch):
    calls = []

    def execute_query(query, params=None):
        calls.append((query, params))
        from werkzeug.security import generate_password_hash

        return [(7, "alice", generate_password_hash("password"))]

    monkeypatch.setattr("opperation.execute_query", execute_query)

    assert auth_user("alice' OR 1=1 --", "password") == {
        "uid": 7,
        "username": "alice",
    }
    assert calls[0][1] == ("alice' OR 1=1 --", "alice' OR 1=1 --")
    assert "%s" in calls[0][0]


def test_register_inserts_new_user_without_client_supplied_uid(monkeypatch):
    calls = []

    def execute_query(query, params=None):
        calls.append((query, params))
        return ()

    monkeypatch.setattr("opperation.execute_query", execute_query)

    assert register({
        "username": "alice",
        "password": "password",
        "email": "alice@example.com",
    }) is True
    assert calls[0][1][0] == "alice"
    assert calls[0][1][2] == "alice@example.com"
    assert calls[0][1][1] != "password"
    assert "CURDATE()" in calls[0][0]


def test_get_users_uses_parameterized_lookup(monkeypatch):
    calls = []

    def execute_query(query, params=None):
        calls.append((query, params))
        return [(7, "alice", "alice@example.com")]

    monkeypatch.setattr("opperation.execute_query", execute_query)

    assert get_users("alice' OR 1=1 --") == [(7, "alice", "alice@example.com")]
    assert calls[0][1] == ("alice' OR 1=1 --", "alice' OR 1=1 --")
