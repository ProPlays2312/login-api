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
        return None

def login(username, password):
    query = (f"SELECT * FROM users WHERE username='{username}' AND password='{password}'")
    result = execute_query(query)
    try:
        if len(result) > 0:
            return True
        else:
            raise Exception("Invalid credentials")
    except Exception as e:
        print(f"Error: {e}")
        return False

def register(username, password):
    query = (f"INSERT INTO users (username, password) VALUES ('{username}', '{password}')")
    result = execute_query(query)
    try:
        if result is not None:
            return True
        else:
            raise Exception("Error registering user")
    except Exception as e:
        print(f"Error: {e}")
        return False
    
