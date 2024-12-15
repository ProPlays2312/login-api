#Description: 

from db import get_connection, execute_query

def create_tables():
    query = """
    CREATE TABLE users (
        uid INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) NOT NULL,
        password VARCHAR(50) NOT NULL,
        email VARCHAR(50) NOT NULL,
        c_date DATE NOT NULL
    );
    CREATE TABLE tokens (
        uid INT NOT NULL,
        md5 VARCHAR(32) NOT NULL,
        cr_date DATE NOT NULL
    );
    """
    try:
        execute_query(query)
    except Exception as e:
        return f"Error: {e}"

def db_init():
    query = "SHOW TABLES;"
    result = execute_query(query)
    if "users" or "tokens" not in result:
        create_tables()