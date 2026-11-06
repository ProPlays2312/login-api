from dotenv import load_dotenv
from werkzeug.security import check_password_hash, generate_password_hash

from api.db import execute_query

load_dotenv(dotenv_path=".env")


def auth_user(login, password):
    query = (
        "SELECT uid, username, password FROM users "
        "WHERE username=%s OR email=%s"
    )
    result = execute_query(query, (login, login))
    if not result:
        return None

    uid, username, password_hash = result[0]
    if not check_password_hash(password_hash, password):
        return None
    return {"uid": uid, "username": username}


def register(data):
    username = data.get("username")
    password = data.get("password")
    email = data.get("email")
    if not all(
        isinstance(value, str) and value.strip()
        for value in (username, password, email)
    ):
        raise ValueError("username, password, and email are required")

    query = (
        "INSERT INTO users (username, password, email, c_date) "
        "VALUES (%s, %s, %s, CURDATE())"
    )
    execute_query(
        query,
        (username.strip(), generate_password_hash(password), email.strip()),
    )
    return True


def get_users(data):
    if isinstance(data, int):
        query = "SELECT uid, username, email FROM users WHERE uid=%s"
        params = (data,)
    elif data is None:
        query = "SELECT uid, username, email FROM users"
        params = None
    elif isinstance(data, str):
        query = (
            "SELECT uid, username, email FROM users "
            "WHERE username=%s OR email=%s"
        )
        params = (data, data)
    else:
        raise ValueError("User lookup must be an ID, username, email, or None")

    result = execute_query(query, params)
    return result or None
