import pytest
from werkzeug.security import generate_password_hash
import opperation


def test_auth_user_hashed_password_success(monkeypatch):
    hashed = generate_password_hash("mysecretpassword")
    mock_db_return = [{"uid": 1, "username": "alice", "email": "alice@example.com", "password": hashed}]

    captured_query = []

    def mock_execute(query, params=None):
        captured_query.append((query, params))
        return mock_db_return

    monkeypatch.setattr(opperation, "execute_query", mock_execute)

    user = opperation.auth_user("alice", "mysecretpassword")
    assert user is not None
    assert user["username"] == "alice"
    assert user["uid"] == 1
    # Ensure sensitive password hash is not leaked
    assert "password" not in user
    # Check that parameterized query was used
    assert len(captured_query) == 1
    assert "%s" in captured_query[0][0]
    assert captured_query[0][1] == ("alice", "alice")


def test_auth_user_plaintext_fallback_success(monkeypatch):
    mock_db_return = [{"uid": 2, "username": "bob", "email": "bob@example.com", "password": "legacy_plaintext"}]
    monkeypatch.setattr(opperation, "execute_query", lambda q, p=None: mock_db_return)

    user = opperation.auth_user("bob", "legacy_plaintext")
    assert user is not None
    assert user["username"] == "bob"
    assert "password" not in user


def test_auth_user_wrong_password(monkeypatch):
    hashed = generate_password_hash("correctpassword")
    mock_db_return = [{"uid": 1, "username": "alice", "email": "alice@example.com", "password": hashed}]
    monkeypatch.setattr(opperation, "execute_query", lambda q, p=None: mock_db_return)

    user = opperation.auth_user("alice", "wrongpassword")
    assert user is None


def test_auth_user_not_found(monkeypatch):
    monkeypatch.setattr(opperation, "execute_query", lambda q, p=None: [])
    user = opperation.auth_user("nobody", "pwd")
    assert user is None


def test_register_invalid_payload():
    assert opperation.register("invalid_string") is False
    assert opperation.register({"username": None, "password": "123", "email": "a@b.com"}) is False


def test_register_success(monkeypatch):
    executed_queries = []

    def mock_execute(query, params=None):
        executed_queries.append((query, params))
        if "INSERT INTO users" in query:
            return [{"uid": 42}]
        return ()

    monkeypatch.setattr(opperation, "execute_query", mock_execute)

    payload = {"username": "charlie", "password": "securepassword", "email": "charlie@example.com"}
    success = opperation.register(payload)
    assert success is True
    assert len(executed_queries) == 2
    # Verify user insert used parameterized placeholders and hashed password
    user_query, user_params = executed_queries[0]
    assert "INSERT INTO users" in user_query
    assert "%s" in user_query
    assert user_params[0] == "charlie"  # username
    assert user_params[1] != "securepassword"  # password MUST be hashed!
    assert user_params[2] == "charlie@example.com"  # email


def test_get_users_all(monkeypatch):
    mock_users = [{"uid": 1, "username": "alice"}, {"uid": 2, "username": "bob"}]
    monkeypatch.setattr(opperation, "execute_query", lambda q, p=None: mock_users)

    result = opperation.get_users()
    assert result == mock_users


def test_get_users_by_uid(monkeypatch):
    captured = []

    def mock_execute(query, params=None):
        captured.append((query, params))
        return [{"uid": 1, "username": "alice"}]

    monkeypatch.setattr(opperation, "execute_query", mock_execute)

    result = opperation.get_users(1)
    assert result == [{"uid": 1, "username": "alice"}]
    assert captured[0][1] == (1,)


def test_create_otp_success(monkeypatch):
    mock_user = [{"uid": 5, "username": "dave", "email": "dave@example.com"}]
    monkeypatch.setattr(opperation, "get_users", lambda ident: mock_user)
    monkeypatch.setattr(opperation, "execute_query", lambda q, p=None: ())

    res, err = opperation.create_otp("dave")
    assert err is None
    assert res is not None
    assert len(res["otp"]) == 6
    assert res["otp"].isdigit()
    assert res["email"] == "dave@example.com"


def test_create_otp_user_not_found(monkeypatch):
    monkeypatch.setattr(opperation, "get_users", lambda ident: [])
    res, err = opperation.create_otp("nonexistent")
    assert res is None
    assert err == "User not found"


def test_verify_otp_success(monkeypatch):
    mock_user = [{"uid": 5, "username": "dave", "email": "dave@example.com"}]
    mock_otp_row = [{"id": 1, "uid": 5, "email": "dave@example.com", "otp_code": "123456"}]

    monkeypatch.setattr(opperation, "get_users", lambda ident: mock_user)

    captured_updates = []

    def mock_exec(query, params=None):
        if "SELECT id" in query:
            return mock_otp_row
        if "UPDATE otps" in query:
            captured_updates.append(params)
            return ()
        return ()

    monkeypatch.setattr(opperation, "execute_query", mock_exec)

    user, err = opperation.verify_otp("dave", "123456")
    assert err is None
    assert user["username"] == "dave"
    assert len(captured_updates) == 1
    assert captured_updates[0] == (1,)


def test_verify_otp_invalid_or_expired(monkeypatch):
    mock_user = [{"uid": 5, "username": "dave", "email": "dave@example.com"}]
    monkeypatch.setattr(opperation, "get_users", lambda ident: mock_user)
    monkeypatch.setattr(opperation, "execute_query", lambda q, p=None: [])

    user, err = opperation.verify_otp("dave", "999999")
    assert user is None
    assert err == "Invalid or expired OTP"


def test_mailer_missing_credentials(monkeypatch):
    from api.mailer import send_otp_email
    monkeypatch.delenv("RESEND_API_KEY", raising=False)
    monkeypatch.delenv("GMAIL_USER", raising=False)
    monkeypatch.delenv("GMAIL_APP_PASSWORD", raising=False)
    monkeypatch.delenv("SMTP_EMAIL", raising=False)
    monkeypatch.delenv("SMTP_APP_PASSWORD", raising=False)
    success, err = send_otp_email("test@example.com", "123456")
    assert success is False
    assert "not configured" in err


def test_mailer_resend_mocked_success(monkeypatch):
    import io
    import urllib.request
    from api.mailer import send_otp_email

    monkeypatch.setenv("RESEND_API_KEY", "re_test_mock_key_123")
    monkeypatch.delenv("GMAIL_USER", raising=False)
    monkeypatch.delenv("GMAIL_APP_PASSWORD", raising=False)
    monkeypatch.delenv("SMTP_EMAIL", raising=False)
    monkeypatch.delenv("SMTP_APP_PASSWORD", raising=False)

    class MockHTTPResponse:
        def __init__(self):
            self.status = 200

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            pass

        def read(self):
            return b'{"id": "mock-email-id-123"}'

    monkeypatch.setattr(urllib.request, "urlopen", lambda req, timeout=10: MockHTTPResponse())

    success, err = send_otp_email("recipient@example.com", "998877")
    assert success is True
    assert err is None


def test_mailer_smtp_mocked_success(monkeypatch):
    import smtplib
    from api.mailer import send_otp_email

    monkeypatch.setenv("GMAIL_USER", "vault@gmail.com")
    monkeypatch.setenv("GMAIL_APP_PASSWORD", "mockapppassword16")

    class MockSMTP:
        def __init__(self, host, port, timeout=10):
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            pass

        def ehlo(self):
            pass

        def starttls(self):
            pass

        def login(self, user, pwd):
            pass

        def send_message(self, msg):
            pass

    monkeypatch.setattr(smtplib, "SMTP", MockSMTP)
    success, err = send_otp_email("recipient@example.com", "888999", "Recipient")
    assert success is True
    assert err is None


def test_mailer_smtp_email_env_success(monkeypatch):
    import smtplib
    from api.mailer import send_otp_email

    monkeypatch.delenv("GMAIL_USER", raising=False)
    monkeypatch.delenv("GMAIL_APP_PASSWORD", raising=False)
    monkeypatch.setenv("SMTP_EMAIL", "vault-smtp@gmail.com")
    monkeypatch.setenv("SMTP_APP_PASSWORD", "smtpappsecret1234")

    class MockSMTP:
        def __init__(self, host, port, timeout=10):
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            pass

        def ehlo(self):
            pass

        def starttls(self):
            pass

        def login(self, user, pwd):
            assert user == "vault-smtp@gmail.com"
            assert pwd == "smtpappsecret1234"

        def send_message(self, msg):
            pass

    monkeypatch.setattr(smtplib, "SMTP", MockSMTP)
    success, err = send_otp_email("recipient@example.com", "112233")
    assert success is True
    assert err is None


def test_create_otp_account_deactivated(monkeypatch):
    mock_user = [{"uid": 5, "username": "dave", "email": "dave@example.com", "is_active": False}]
    monkeypatch.setattr(opperation, "get_users", lambda ident: mock_user)
    res, err = opperation.create_otp("dave")
    assert res is None
    assert err == "Account is deactivated"


def test_create_otp_cooldown_active(monkeypatch):
    from datetime import datetime, timedelta
    mock_user = [{"uid": 5, "username": "dave", "email": "dave@example.com", "is_active": True}]
    monkeypatch.setattr(opperation, "get_users", lambda ident: mock_user)

    # Mock DB return where created_at was 20 seconds ago
    recent_time = datetime.now() - timedelta(seconds=20)

    def mock_exec(query, params=None):
        if "COUNT(*)" in query:
            return [{"otp_count": 1}]
        if "SELECT created_at FROM otps" in query:
            return [{"created_at": recent_time}]
        return ()

    monkeypatch.setattr(opperation, "execute_query", mock_exec)

    res, err = opperation.create_otp("dave")
    assert "cooldown_remaining" in res
    assert res["cooldown_remaining"] > 0
    assert "Please wait" in err


def test_create_otp_rate_limit_exceeded(monkeypatch):
    mock_user = [{"uid": 5, "username": "dave", "email": "dave@example.com", "is_active": True}]
    monkeypatch.setattr(opperation, "get_users", lambda ident: mock_user)

    def mock_exec(query, params=None):
        if "COUNT(*)" in query:
            return [{"otp_count": 5}]
        return ()

    monkeypatch.setattr(opperation, "execute_query", mock_exec)

    res, err = opperation.create_otp("dave")
    assert res.get("rate_limited") is True
    assert "Rate limit exceeded" in err
