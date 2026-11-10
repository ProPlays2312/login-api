import time
from api.token import generate_token, session_token, verify_token


def test_generate_token():
    user_data = {"username": "alice", "uid": 42}
    token, c_date = generate_token(user_data)
    assert isinstance(token, str)
    assert len(token) == 32
    assert c_date == time.strftime("%Y-%m-%d")


def test_session_token_and_verify_valid():
    md5_hash = "098f6bcd4621d373cade4e832627b4f6"
    token = session_token(md5_hash)
    assert token.startswith(md5_hash + ".")
    assert verify_token(token) is True


def test_verify_token_expired():
    md5_hash = "098f6bcd4621d373cade4e832627b4f6"
    expired_timestamp = int(time.time()) - 3600
    expired_token = f"{md5_hash}.{expired_timestamp}"
    assert verify_token(expired_token) is False
