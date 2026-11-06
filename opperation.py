from dotenv import load_dotenv
from api.db import execute_query
from api.utils import not_null

load_dotenv(dotenv_path=".env")

def auth_user(login, password):
    query = (
        "SELECT uid, username FROM users "
        "WHERE (username=%s OR email=%s) AND password=%s"
    )
    result = execute_query(query, (login, login, password))
    if not result:
        return None
    uid, username = result[0]
    return {"uid": uid, "username": username}

def register(data):
    username = not_null(data.get("username"))
    password = not_null(data.get("password"))
    email = not_null(data.get("email"))
    query = (
        "INSERT INTO users (username, password, email, c_date) "
        "VALUES (%s, %s, %s, CURDATE())"
    )
    execute_query(query, (username, password, email))
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
