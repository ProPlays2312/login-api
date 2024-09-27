import pymysql
import os
from dotenv import load_dotenv

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
    query = (f"INSERT INTO users (username, password, email) VALUES ('{username}', '{password}', '{email}')")
    try:
        result = execute_query(query)
        if result is not None:
            return True
        else:
            raise Exception("Error registering user")
    except Exception as e:
        print(f"Error: {e}")
        return False
    
def get_users():
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