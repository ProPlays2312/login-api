import time
from api.token import generate_token, session_token, verify_token


def test_generate_token():
    user_data = {"username": "alice", "uid": 42}
    token, c_date = generate_token(user_data)
    assert isinstance(token, str)
    assert len(token) == 64
    assert c_date == time.strftime("%Y-%m-%d")


def test_session_token_and_verify_valid():
    data = {"username": "alice", "uid": 42}
    token_digest, _ = generate_token(data)
    token = session_token(token_digest)
    assert token.startswith(token_digest + ".")
    assert verify_token(token, data) is True


def test_verify_token_expired():
    data = {"username": "alice", "uid": 42}
    token_digest, _ = generate_token(data)
    expired_timestamp = int(time.time()) - 3600
    expired_token = f"{token_digest}.{expired_timestamp}"
    assert verify_token(expired_token, data) is False


def test_verify_token_rejects_malformed_token():
    data = {"username": "alice", "uid": 42}
    assert verify_token("not-a-token", data) is False
    assert verify_token("0" * 32 + ".9999999999", data) is False


def test_verify_token_rejects_forged_digest():
    data = {"username": "alice", "uid": 42}
    assert verify_token("0" * 64 + ".9999999999", data) is False
