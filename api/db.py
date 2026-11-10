# Description: This file contains the database connection function.

import psycopg2
import psycopg2.extras
import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(dotenv_path=Path(__file__).resolve().parent.parent / ".env")
load_dotenv()


def get_connection():
    try:
        database_url = os.getenv("DATABASE_URL")
        if database_url:
            connect_kwargs = {"cursor_factory": psycopg2.extras.RealDictCursor}
            if "sslmode=" not in database_url:
                connect_kwargs["sslmode"] = os.getenv("DB_SSLMODE", "require" if (
                    "supabase" in database_url or "prisma" in database_url) else "prefer")
            return psycopg2.connect(database_url, **connect_kwargs)

        host = os.getenv("DB_HOST", "localhost")
        port = int(os.getenv("DB_PORT", "5432") or 5432)
        user = os.getenv("DB_USER", "postgres")
        password = os.getenv("DB_PASS", "")
        database = os.getenv("DB_NAME", "postgres")
        sslmode = os.getenv("DB_SSLMODE", "require" if "supabase" in host else "prefer")

        connection = psycopg2.connect(
            host=host,
            port=port,
            user=user,
            password=password,
            dbname=database,
            sslmode=sslmode,
            cursor_factory=psycopg2.extras.RealDictCursor
        )
        return connection
    except Exception as e:
        print(f"Error: {e}")
        return None


def execute_query(query, params=None):
    connection = get_connection()
    if connection is not None:
        try:
            with connection.cursor() as cursor:
                if params is not None:
                    cursor.execute(query, params)
                else:
                    cursor.execute(query)
                if cursor.description is not None:
                    result = cursor.fetchall()
                else:
                    result = ()
                connection.commit()
                return result
        except Exception as e:
            try:
                connection.rollback()
            except Exception:
                pass
            return f"Error: {e}"
        finally:
            connection.close()
    else:
        raise Exception("Error connecting to database")
