import pymysql
import os
from dotenv import load_dotenv
from datetime import datetime
from flask import jsonify
import jwt
from datetime import timedelta

load_dotenv(dotenv_path=".env")

def get_connection():
    try:
        connection = pymysql.connect(
            host=os.getenv("DB_HOST"),
            user=os.getenv("DB_USER"),
            password=os.getenv("DB_PASSWORD"),
            database=os.getenv("DB_NAME"),
            cursorclass=pymysql.cursors.DictCursor
        )
        return connection
    except Exception as e:
        print(f"Error: {e}")
        return None

def execute_query(query):
    connection = get_connection()
    if connection is not None:
        try:
            with connection.cursor() as cursor:
                cursor.execute(query)
                result = cursor.fetchall()
                connection.commit()
                return result
        except Exception as e:
            print(f"Error: {e}")
            return None
        finally:
            connection.close()
    else:
        raise Exception("Error connecting to database")

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

def create_jwt(data):
    # Create a JWT token
    pass

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
    jwt = create_jwt({"username": username, "email": email})
    query = (f"INSERT INTO users (username, password, email, c_date, jwt) VALUES ('{username}', '{password}', '{email}', '{c_date}', '{jwt}')")
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
    if id is not None:
        query = f"SELECT uid, username, email FROM users WHERE uid={id}"
    else:
        query = "SELECT uid, username, email FROM users"
    result = execute_query(query)
    try:
        if result is not None:
            return result
        else:
            raise Exception("Error getting users")
    except Exception as e:
        print(f"Error: {e}")
        return None
    
data={"username": "admin", "password": "password@123", "email": "admin@local.co"}
try:
    create_jwt(data)
except Exception as e:
    print(f"Error: {e}")
    pass
