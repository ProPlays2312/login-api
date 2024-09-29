# Description: This file contains the database connection function.
import pymysql
import os
from dotenv import load_dotenv

load_dotenv(dotenv_path="../.env")

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