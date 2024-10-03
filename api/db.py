# Description: This file contains the database connection function.

import pymysql
import os
from dotenv import load_dotenv

load_dotenv(dotenv_path="../.env")

def get_connection():
    try:
        connection = pymysql.connect(
            host=os.getenv("DB_HOST"),
            port=int(os.getenv("DB_PORT")),
            user=os.getenv("DB_USER"),
            password=os.getenv("DB_PASS"),
            db=os.getenv("DB_NAME"),
            charset='utf8mb4',
            ssl_ca= "ca.pem"
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
            return(f"Error: {e}")
        finally:
            connection.close()
    else:
        raise Exception("Error connecting to database")
