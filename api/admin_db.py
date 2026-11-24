"""Admin database schema: audit_logs and admin_settings tables."""
from api.db import execute_query
from api.utils import safe_print

def create_admin_tables():
    audit_logs_table = """
    CREATE TABLE IF NOT EXISTS audit_logs (
        id SERIAL PRIMARY KEY,
        event_type VARCHAR(50) NOT NULL,
        actor_uid INT,
        actor_username VARCHAR(100),
        target_uid INT,
        target_username VARCHAR(100),
        ip_address VARCHAR(50) DEFAULT '127.0.0.1',
        status VARCHAR(20) DEFAULT 'Success',
        details TEXT,
        created_at TIMESTAMP NOT NULL DEFAULT NOW()
    );
    """
    admin_settings_table = """
    CREATE TABLE IF NOT EXISTS admin_settings (
        id SERIAL PRIMARY KEY,
        setting_key VARCHAR(100) NOT NULL UNIQUE,
        setting_value TEXT,
        updated_at TIMESTAMP NOT NULL DEFAULT NOW()
    );
    """
    try:
        execute_query(audit_logs_table)
        execute_query(admin_settings_table)
        execute_query("CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_logs(actor_uid);")
        execute_query("CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at DESC);")
        # Seed default settings if not present
        defaults = [
            ("session_timeout", "3600"),
            ("max_failed_attempts", "5"),
            ("otp_expiry_seconds", "300"),
            ("password_min_length", "8"),
            ("mfa_required", "true"),
            ("app_name", "VaultAuth SSO"),
            ("app_version", "1.0.0"),
        ]
        for key, val in defaults:
            execute_query(
                "INSERT INTO admin_settings (setting_key, setting_value) VALUES (%s, %s) ON CONFLICT (setting_key) DO NOTHING",
                (key, val)
            )
        return True
    except Exception as e:
        safe_print(f"Admin DB init error: {e}")
        return False

def init_admin_db():
    try:
        create_admin_tables()
    except Exception as e:
        safe_print(f"Admin DB init failed: {e}")
