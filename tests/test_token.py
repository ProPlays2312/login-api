import time
from api.token import generate_token, session_token, verify_token


def test_generate_token():
    user_data = {"username": "alice", "uid": 42}
    token, c_date = generate_token(user_data)
    assert isinstance(token, str)
    assert len(token) == 64
    assert c_date == time.strftime("%Y-%m-%d")


def test_session_token_and_verify_valid():
    token_digest = "0" * 64
    token = session_token(token_digest)
    assert token.startswith(token_digest + ".")
    assert verify_token(token) is True


def test_verify_token_expired():
    token_digest = "0" * 64
    expired_timestamp = int(time.time()) - 3600
    expired_token = f"{token_digest}.{expired_timestamp}"
    assert verify_token(expired_token) is False


def test_verify_token_rejects_malformed_token():
    assert verify_token("not-a-token") is False
    assert verify_token("0" * 32 + ".9999999999") is False
