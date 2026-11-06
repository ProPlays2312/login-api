import os

import pymysql
from dotenv import load_dotenv

load_dotenv(dotenv_path="../.env")


def get_connection():
    return pymysql.connect(
        host=os.getenv("DB_HOST"),
        port=int(os.getenv("DB_PORT")),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASS"),
        db=os.getenv("DB_NAME"),
        charset="utf8mb4",
        ssl_ca="ca.pem",
        connect_timeout=10,
        read_timeout=10,
        write_timeout=10,
    )


def execute_query(query, params=None):
    connection = get_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute(query, params)
            result = cursor.fetchall() if cursor.description is not None else []
        connection.commit()
        return result
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
