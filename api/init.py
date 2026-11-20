# Description:

from api.db import execute_query
from api.utils import safe_print


def create_tables():
    users_table = """
    CREATE TABLE IF NOT EXISTS users (
        uid SERIAL PRIMARY KEY,
        username VARCHAR(50) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        email VARCHAR(100) NOT NULL UNIQUE,
        full_name VARCHAR(100),
        phone VARCHAR(20),
        is_active BOOLEAN DEFAULT TRUE,
        c_date DATE NOT NULL
    );
    """
    tokens_table = """
    CREATE TABLE IF NOT EXISTS tokens (
        uid INT NOT NULL,
        md5 VARCHAR(32) NOT NULL,
        cr_date DATE NOT NULL
    );
    """
    otps_table = """
    CREATE TABLE IF NOT EXISTS otps (
        id SERIAL PRIMARY KEY,
        uid INT NOT NULL,
        email VARCHAR(100),
        phone VARCHAR(20),
        otp_code VARCHAR(10) NOT NULL,
        created_at TIMESTAMP NOT NULL,
        expires_at TIMESTAMP NOT NULL,
        used BOOLEAN DEFAULT FALSE
    );
    """
    try:
        execute_query(users_table)
        execute_query(tokens_table)
        execute_query(otps_table)
        # Migrate existing tables if they don't have phone, full_name, or is_active column yet
        execute_query("ALTER TABLE users ADD COLUMN IF NOT EXISTS full_name VARCHAR(100);")
        execute_query("ALTER TABLE users ADD COLUMN IF NOT EXISTS phone VARCHAR(20);")
        execute_query("ALTER TABLE users ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT TRUE;")
        execute_query("CREATE UNIQUE INDEX IF NOT EXISTS users_email_unique ON users(email);")
        execute_query("UPDATE users SET is_active = TRUE WHERE is_active IS NULL;")
        execute_query("ALTER TABLE otps ADD COLUMN IF NOT EXISTS phone VARCHAR(20);")
        execute_query("ALTER TABLE otps ADD COLUMN IF NOT EXISTS otp_hash VARCHAR(64);")
        execute_query("ALTER TABLE otps ADD COLUMN IF NOT EXISTS attempts INT DEFAULT 0;")
        execute_query("ALTER TABLE users ADD COLUMN IF NOT EXISTS role VARCHAR(20) DEFAULT 'user';")
        execute_query("CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);")
        execute_query("UPDATE users SET role = 'user' WHERE role IS NULL;")
        return True
    except Exception as e:
        return f"Error: {e}"


def db_init():
    try:
        create_tables()
    except Exception as e:
        safe_print(f"Error initializing DB: {e}")
