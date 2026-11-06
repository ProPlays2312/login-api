# Description: This file contains the functions to generate and verify the session token.

from dotenv import load_dotenv
import os
import time
import hmac
import hashlib

load_dotenv(dotenv_path="../.env")


def generate_token(data):
    c_date = time.strftime("%Y-%m-%d")
    token_digest = hmac.new(
        os.getenv("TOKEN_SECRET").encode(),
        f"{data['username']}{data['uid']}".encode(),
        hashlib.sha256,
    ).hexdigest()
    return token_digest, c_date


def session_token(token_digest):
    expiration = int(time.time()) + int(os.getenv("TOKEN_EXPIRATION"))
    token = token_digest + "." + str(expiration)
    return token


def verify_token(token, data):
    try:
        token_digest, expiration = token.split(".", 1)
        if len(token_digest) != 64:
            return False
        int(token_digest, 16)
        expiration = int(expiration)
    except (AttributeError, ValueError):
        return False
    expected_digest, _ = generate_token(data)
    if expiration < int(time.time()) or not hmac.compare_digest(
        token_digest, expected_digest
    ):
        return False
    return True