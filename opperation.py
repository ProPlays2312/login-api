import pymysql
import os
from dotenv import load_dotenv
from datetime import datetime
from api.db import execute_query

load_dotenv(dotenv_path=".env")

def not_null(value):
    try:
        if value is not None:
            return value
        else:
            raise Exception("Value is null")
    except Exception as e:
        print(f"Error: {e}")
        return None

def is_email(email):
    try:
        if "@" in email:
            return email
        else:
            return None
    except Exception as e:
        print(f"Error: {e}")
        return None

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
    token = "TODO: Generate token"
    query = (f"INSERT INTO users (username, password, email, c_date, jwt) VALUES ('{username}', '{password}', '{email}', '{c_date}')")
    query2 = "TODO: Insert token"
    try:
        result = execute_query(query)
        if result is not None:
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
        raise Exception("Invalid id")
    result = execute_query(query)
    try:
        if result is not None:
            return result
        else:
            raise Exception("Error getting users")
    except Exception as e:
        print(f"Error: {e}")
        return None
    
