# Description: This file contains the functions to generate and verify the session token.

from dotenv import load_dotenv
import os
import time
import hashlib
from pathlib import Path

load_dotenv(dotenv_path=Path(__file__).resolve().parent.parent / ".env")
load_dotenv()


def generate_token(data, uid=None):
    c_date = time.strftime("%Y-%m-%d")
    if isinstance(data, dict):
        username = data.get("username") or data.get("user") or ""
        user_uid = data.get("uid") if data.get("uid") is not None else data.get("id", "")
    else:
        username = str(data)
        user_uid = uid if uid is not None else ""

    secret = os.getenv("TOKEN_SECRET", "default-secret-token")
    md5sum = hashlib.md5(f"{username}:{user_uid}".encode())
    md5sum.update(secret.encode())
    md5sum = md5sum.hexdigest()
    return md5sum, c_date


def session_token(md5sum):
    if isinstance(md5sum, (tuple, list)):
        md5sum = md5sum[0]
    expiration_seconds = int(os.getenv("TOKEN_EXPIRATION", "3600") or 3600)
    expiration = int(time.time()) + expiration_seconds
    token = f"{md5sum}.{expiration}"
    return token


def verify_token(token):
    try:
        if not token or not isinstance(token, str):
            return False
        parts = token.strip().split(".")
        if len(parts) != 2:
            return False
        md5sum, expiration = parts[0].strip(), parts[1].strip()
        if not md5sum or not expiration:
            return False
        if not md5sum.isalnum():
            return False
        if not expiration.isdigit():
            return False
        if int(expiration) < int(time.time()):
            return False
        return True
    except (ValueError, TypeError, AttributeError):
        return False
