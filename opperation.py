from dotenv import load_dotenv
from datetime import datetime

from api.db import execute_query
from api.utils import not_null
from api.token import generate_token

load_dotenv(dotenv_path=".env")

def auth_user(login, password):
    query = (f"SELECT * FROM users WHERE username='{login}' OR email='{login}' AND password='{password}'")
    result = execute_query(query)
    try:
        if len(result) > 0:
            return True
        else:
            raise Exception("Invalid credentials")
    except Exception as e:
        print(f"Error: {e}")
        return False

def register(data):
    username = not_null(data.get("username"))
    password = not_null(data.get("password"))
    email = not_null(data.get("email"))
    c_date = datetime.now().strftime("%Y-%m-%d")
    data = generate_token(data["username"], data["uid"])
    token = data[0]
    c_date = data[1]
    query = f"INSERT INTO users (username, password, email, c_date) VALUES ('{username}', '{password}', '{email}', '{c_date}')"
    query2 = f"INSERT INTO tokens (uid, md5, cr_date) VALUES ({data.get('uid')}, '{token}', '{c_date}')"
    try:
        result = execute_query(query)
        result2 = execute_query(query2)
        if result and result2 is not None:
            return True
        else:
            raise Exception("Error registering user")
    except Exception as e:
        print(f"Error: {e}")
        return False
    
def get_users(id):
    if id is int:
        query = f"SELECT uid, username, email FROM users WHERE uid={id}"
    if id is None:
        query = "SELECT uid, username, email FROM users"
    if id is str:
        query = f"SELECT uid, username, email FROM users WHERE username='{id}' OR email='{id}'"
    else:
        raise Exception("Invalid Request")
    result = execute_query(query)
    try:
        if result is not None:
            return result
        else:
            raise Exception("Error getting users")
    except Exception as e:
        print(f"Error: {e}")
        return None
    
