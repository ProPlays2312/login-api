"""Database initialization and schema definitions for WebAuthn / FIDO2 Passkeys."""

from api.db import execute_query
from api.utils import safe_print


def create_webauthn_tables():
    """Create all tables required for WebAuthn/FIDO2 passkey credentials and challenges."""
    
    # 1. WebAuthn Registered Credentials
    webauthn_credentials_table = """
    CREATE TABLE IF NOT EXISTS webauthn_credentials (
        id SERIAL PRIMARY KEY,
        uid INT NOT NULL,
        credential_id VARCHAR(512) UNIQUE NOT NULL,
        public_key BYTEA NOT NULL,
        sign_count INT NOT NULL DEFAULT 0,
        device_name VARCHAR(100) DEFAULT 'Passkey',
        transports VARCHAR(255),
        aaguid VARCHAR(64),
        created_at TIMESTAMP NOT NULL DEFAULT NOW(),
        last_used_at TIMESTAMP,
        CONSTRAINT fk_webauthn_user FOREIGN KEY (uid) REFERENCES users(uid) ON DELETE CASCADE
    );
    """

    # 2. Ephemeral Challenges (single-use, short-lived)
    webauthn_challenges_table = """
    CREATE TABLE IF NOT EXISTS webauthn_challenges (
        id SERIAL PRIMARY KEY,
        challenge_str VARCHAR(255) UNIQUE NOT NULL,
        challenge_bytes BYTEA NOT NULL,
        uid INT,
        challenge_type VARCHAR(20) NOT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT NOW(),
        expires_at TIMESTAMP NOT NULL
    );
    """

    try:
        execute_query(webauthn_credentials_table)
        execute_query(webauthn_challenges_table)

        # Performance and integrity indexes
        execute_query("CREATE INDEX IF NOT EXISTS idx_webauthn_uid ON webauthn_credentials(uid);")
        execute_query("CREATE INDEX IF NOT EXISTS idx_webauthn_cred_id ON webauthn_credentials(credential_id);")
        execute_query("CREATE INDEX IF NOT EXISTS idx_webauthn_challenge_str ON webauthn_challenges(challenge_str);")
        execute_query("CREATE INDEX IF NOT EXISTS idx_webauthn_challenge_exp ON webauthn_challenges(expires_at);")

        return True
    except Exception as e:
        safe_print(f"Error creating WebAuthn tables: {e}")
        return False


def init_webauthn_db():
    """Initialize WebAuthn tables."""
    try:
        create_webauthn_tables()
    except Exception as e:
        safe_print(f"WebAuthn DB init error: {e}")
