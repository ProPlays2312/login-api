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

def session_token(md5sum):
    expiration = int(time.time()) + int(os.getenv("TOKEN_EXPIRATION"))
    token = md5sum + "." + str(expiration)
    return token
    
def verify_token(token):
    md5sum, expiration = token.split(".")
    if int(expiration) < int(time.time()):
        return False
    else:
        return True
    