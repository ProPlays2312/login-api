"""Database initialization and schema definitions for VaultAuth Dashboard."""

from api.db import execute_query
from api.utils import safe_print


def create_dashboard_tables():
    """Create all tables required for the VaultAuth End User Dashboard."""
    
    # 1. Active Sessions
    active_sessions_table = """
    CREATE TABLE IF NOT EXISTS active_sessions (
        id SERIAL PRIMARY KEY,
        uid INT NOT NULL,
        session_id VARCHAR(64) UNIQUE NOT NULL,
        session_token VARCHAR(255) NOT NULL,
        device_name VARCHAR(100) NOT NULL,
        device_type VARCHAR(50) DEFAULT 'desktop',
        browser VARCHAR(50) NOT NULL,
        os VARCHAR(50) DEFAULT 'Unknown',
        ip_address VARCHAR(50) DEFAULT '127.0.0.1',
        location VARCHAR(100) DEFAULT 'Bengaluru, India',
        created_at TIMESTAMP NOT NULL DEFAULT NOW(),
        last_activity TIMESTAMP NOT NULL DEFAULT NOW(),
        is_active BOOLEAN NOT NULL DEFAULT TRUE,
        expires_at TIMESTAMP,
        revoked_at TIMESTAMP,
        CONSTRAINT fk_session_user FOREIGN KEY (uid) REFERENCES users(uid) ON DELETE CASCADE
    );
    """

    # 2. Login Activity
    login_activity_table = """
    CREATE TABLE IF NOT EXISTS login_activity (
        id SERIAL PRIMARY KEY,
        uid INT NOT NULL,
        device_name VARCHAR(100) NOT NULL,
        device_type VARCHAR(50) DEFAULT 'desktop',
        browser VARCHAR(50) NOT NULL,
        os VARCHAR(50) DEFAULT 'Unknown',
        location VARCHAR(100) DEFAULT 'Bengaluru, India',
        ip_address VARCHAR(50) DEFAULT '127.0.0.1',
        status VARCHAR(20) NOT NULL DEFAULT 'Success',
        created_at TIMESTAMP NOT NULL DEFAULT NOW(),
        CONSTRAINT fk_activity_user FOREIGN KEY (uid) REFERENCES users(uid) ON DELETE CASCADE
    );
    """

    # 3. Connected Applications
    connected_apps_table = """
    CREATE TABLE IF NOT EXISTS connected_apps (
        id SERIAL PRIMARY KEY,
        uid INT NOT NULL,
        app_key VARCHAR(50) NOT NULL,
        app_name VARCHAR(100) NOT NULL,
        app_desc VARCHAR(255) NOT NULL,
        logo_char VARCHAR(5) NOT NULL,
        logo_bg VARCHAR(20) NOT NULL,
        permissions TEXT NOT NULL,
        connected_at TIMESTAMP NOT NULL DEFAULT NOW(),
        is_active BOOLEAN NOT NULL DEFAULT TRUE,
        CONSTRAINT fk_app_user FOREIGN KEY (uid) REFERENCES users(uid) ON DELETE CASCADE
    );
    """

    # 4. User Security Settings
    user_security_settings_table = """
    CREATE TABLE IF NOT EXISTS user_security_settings (
        id SERIAL PRIMARY KEY,
        uid INT NOT NULL UNIQUE,
        mfa_enabled BOOLEAN NOT NULL DEFAULT TRUE,
        recovery_email VARCHAR(100),
        recovery_email_verified BOOLEAN NOT NULL DEFAULT TRUE,
        password_strength VARCHAR(20) DEFAULT 'Strong',
        password_last_changed TIMESTAMP NOT NULL DEFAULT NOW(),
        department VARCHAR(100) DEFAULT 'Engineering',
        role VARCHAR(100) DEFAULT 'End user',
        joined_date DATE DEFAULT CURRENT_DATE,
        CONSTRAINT fk_sec_user FOREIGN KEY (uid) REFERENCES users(uid) ON DELETE CASCADE
    );
    """

    try:
        execute_query(active_sessions_table)
        execute_query(login_activity_table)
        execute_query(connected_apps_table)
        execute_query(user_security_settings_table)
        
        # Ensure new session columns exist for backward compatibility
        execute_query("ALTER TABLE active_sessions ADD COLUMN IF NOT EXISTS expires_at TIMESTAMP;")
        execute_query("ALTER TABLE active_sessions ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMP;")

        # Create indexes for fast user lookup
        execute_query("CREATE INDEX IF NOT EXISTS idx_sessions_uid ON active_sessions(uid);")
        execute_query("CREATE INDEX IF NOT EXISTS idx_sessions_active ON active_sessions(uid, is_active);")
        execute_query("CREATE INDEX IF NOT EXISTS idx_activity_uid ON login_activity(uid);")
        execute_query("CREATE INDEX IF NOT EXISTS idx_apps_uid ON connected_apps(uid);")
        return True
    except Exception as e:
        safe_print(f"Error creating dashboard tables: {e}")
        return False


def init_dashboard_db():
    """Verify and initialize dashboard tables."""
    try:
        create_dashboard_tables()
    except Exception as e:
        safe_print(f"Dashboard DB init error: {e}")
