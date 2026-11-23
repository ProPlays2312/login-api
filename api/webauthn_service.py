"""Service layer for WebAuthn / FIDO2 Passkey registration and authentication."""

import os
import json
import secrets
from datetime import datetime, timedelta
from typing import Optional, Tuple, Dict, Any, List

from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json,
)
from webauthn.helpers import bytes_to_base64url, base64url_to_bytes
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    ResidentKeyRequirement,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialType,
)

from api.db import execute_query
from api.utils import safe_print
from api.security import log_security_event
from api.admin import record_audit_log


def get_rp_id() -> str:
    """Retrieve Relying Party ID (domain without protocol/port)."""
    return os.getenv("WEBAUTHN_RP_ID", "localhost").strip()


def get_rp_name() -> str:
    """Retrieve Relying Party human-readable name."""
    return os.getenv("WEBAUTHN_RP_NAME", "VaultAuth SSO").strip()


def get_expected_origins() -> List[str]:
    """Retrieve allowed WebAuthn origins."""
    env_origins = os.getenv("WEBAUTHN_ORIGINS") or os.getenv("CORS_ORIGINS", "")
    if env_origins:
        origins = [o.strip() for o in env_origins.split(",") if o.strip()]
        if origins:
            return origins

    return [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5000",
        "http://127.0.0.1:5000",
        "http://localhost:5500",
        "http://127.0.0.1:5500",
    ]


# ─── Challenge Management ───────────────────────────────────────────────────────

def create_webauthn_challenge(uid: Optional[int] = None, challenge_type: str = "registration", expires_in_seconds: int = 300) -> Tuple[bytes, str]:
    """Generate a cryptographically secure random challenge and store it in PostgreSQL."""
    challenge_bytes = secrets.token_bytes(32)
    challenge_str = bytes_to_base64url(challenge_bytes)
    now = datetime.now()
    expires_at = now + timedelta(seconds=expires_in_seconds)

    # Clean up expired challenges
    try:
        execute_query("DELETE FROM webauthn_challenges WHERE expires_at < %s", (now,))
    except Exception as e:
        safe_print(f"[WebAuthn Cleanup Challenge Notice]: {e}")

    # Store fresh challenge
    execute_query(
        """INSERT INTO webauthn_challenges (challenge_str, challenge_bytes, uid, challenge_type, created_at, expires_at)
           VALUES (%s, %s, %s, %s, %s, %s)""",
        (challenge_str, challenge_bytes, uid, challenge_type, now, expires_at)
    )

    return challenge_bytes, challenge_str


def consume_webauthn_challenge(challenge_str: str, expected_type: str = "registration", uid: Optional[int] = None) -> Optional[bytes]:
    """
    Look up, validate, and atomically consume a challenge.
    Single-use: permanently deleted to prevent replay attacks.
    """
    if not challenge_str:
        return None

    now = datetime.now()
    query = """
    SELECT id, challenge_bytes, uid, challenge_type, expires_at
    FROM webauthn_challenges
    WHERE challenge_str = %s AND challenge_type = %s AND expires_at >= %s
    """
    params = [challenge_str, expected_type, now]
    rows = execute_query(query, tuple(params))

    if not isinstance(rows, list) or len(rows) == 0:
        return None

    record = rows[0]
    rec_uid = record.get("uid")

    # If challenge was bound to a specific user, verify UID matches
    if uid is not None and rec_uid is not None and rec_uid != uid:
        return None

    # Delete challenge immediately (single-use guarantee)
    execute_query("DELETE FROM webauthn_challenges WHERE id = %s", (record["id"],))

    raw_bytes = record.get("challenge_bytes")
    if isinstance(raw_bytes, memoryview):
        return bytes(raw_bytes)
    elif isinstance(raw_bytes, (bytes, bytearray)):
        return bytes(raw_bytes)

    # Fallback: decode string
    try:
        return base64url_to_bytes(challenge_str)
    except Exception:
        return None


# ─── Passkey Registration ───────────────────────────────────────────────────────

def get_passkey_registration_options(user: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate WebAuthn registration options for an authenticated user.
    Populates exclude_credentials with user's existing passkeys to prevent duplicates.
    """
    uid = user["uid"]
    username = user.get("username") or f"user_{uid}"
    display_name = user.get("full_name") or username

    # User ID must be binary bytes (W3C spec recommendation: opaque byte sequence)
    user_id_bytes = str(uid).encode("utf-8")

    # Generate single-use challenge bound to this user
    challenge_bytes, challenge_str = create_webauthn_challenge(uid=uid, challenge_type="registration")

    # Find existing credentials for this user to exclude re-registering the same key
    existing_creds = []
    cred_rows = execute_query("SELECT credential_id FROM webauthn_credentials WHERE uid = %s", (uid,))
    if isinstance(cred_rows, list):
        for cr in cred_rows:
            cid_str = cr.get("credential_id")
            if cid_str:
                try:
                    existing_creds.append(
                        PublicKeyCredentialDescriptor(
                            id=base64url_to_bytes(cid_str),
                            type=PublicKeyCredentialType.PUBLIC_KEY,
                        )
                    )
                except Exception:
                    pass

    options = generate_registration_options(
        rp_id=get_rp_id(),
        rp_name=get_rp_name(),
        user_id=user_id_bytes,
        user_name=username,
        user_display_name=display_name,
        challenge=challenge_bytes,
        exclude_credentials=existing_creds if existing_creds else None,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
    )

    # Return as JSON-serializable dictionary
    return json.loads(options_to_json(options))


def verify_and_save_passkey_registration(user: Dict[str, Any], credential_payload: Dict[str, Any], device_name: Optional[str] = None, client_ip: str = "127.0.0.1") -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    """
    Verify browser WebAuthn attestation response and persist credential in database.
    """
    uid = user["uid"]
    username = user.get("username") or f"user_{uid}"

    # Extract client challenge string from clientDataJSON
    client_challenge_str = None
    try:
        client_data_raw = credential_payload.get("response", {}).get("clientDataJSON", "")
        if client_data_raw:
            client_data_json = json.loads(base64url_to_bytes(client_data_raw).decode("utf-8"))
            client_challenge_str = client_data_json.get("challenge")
    except Exception as e:
        safe_print(f"[WebAuthn clientDataJSON Parse Warning]: {e}")

    # Consume matching challenge
    expected_challenge_bytes = consume_webauthn_challenge(
        challenge_str=client_challenge_str,
        expected_type="registration",
        uid=uid
    )

    if not expected_challenge_bytes:
        # Fallback: check if any valid registration challenge exists for user
        now = datetime.now()
        fallback_rows = execute_query(
            "SELECT id, challenge_str, challenge_bytes FROM webauthn_challenges WHERE uid = %s AND challenge_type = 'registration' AND expires_at >= %s ORDER BY id DESC LIMIT 1",
            (uid, now)
        )
        if isinstance(fallback_rows, list) and len(fallback_rows) > 0:
            rec = fallback_rows[0]
            execute_query("DELETE FROM webauthn_challenges WHERE id = %s", (rec["id"],))
            raw_b = rec["challenge_bytes"]
            expected_challenge_bytes = bytes(raw_b) if isinstance(raw_b, (bytes, bytearray, memoryview)) else base64url_to_bytes(rec["challenge_str"])

    if not expected_challenge_bytes:
        record_audit_log("WEBAUTHN_REGISTER_FAILED", actor_uid=uid, actor_username=username,
                         ip_address=client_ip, status="Failed", details="Invalid or expired registration challenge")
        return False, "Registration challenge has expired or is invalid. Please try again.", None

    try:
        verified_registration = verify_registration_response(
            credential=credential_payload,
            expected_challenge=expected_challenge_bytes,
            expected_rp_id=get_rp_id(),
            expected_origin=get_expected_origins(),
            require_user_verification=False,
        )

        credential_id_str = bytes_to_base64url(verified_registration.credential_id)
        public_key_bytes = verified_registration.credential_public_key
        sign_count = verified_registration.sign_count or 0
        aaguid = str(verified_registration.aaguid) if verified_registration.aaguid else None

        # Determine sensible device name if omitted
        resolved_device_name = device_name.strip() if (device_name and device_name.strip()) else "Passkey Authenticator"

        # Extract transports if provided
        transports = None
        raw_transports = credential_payload.get("response", {}).get("transports")
        if isinstance(raw_transports, list):
            transports = ",".join(raw_transports)

        # Store in database
        insert_query = """
        INSERT INTO webauthn_credentials (
            uid, credential_id, public_key, sign_count, device_name, transports, aaguid, created_at, last_used_at
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, NOW(), NOW())
        RETURNING id, credential_id, device_name, created_at
        """
        res = execute_query(insert_query, (
            uid,
            credential_id_str,
            public_key_bytes,
            sign_count,
            resolved_device_name,
            transports,
            aaguid
        ))

        if isinstance(res, str) and res.startswith("Error:"):
            return False, f"Failed to save passkey: {res}", None

        cred_record = res[0] if (isinstance(res, list) and len(res) > 0) else {}

        record_audit_log(
            "WEBAUTHN_REGISTER_SUCCESS",
            actor_uid=uid,
            actor_username=username,
            ip_address=client_ip,
            status="Success",
            details=f"device={resolved_device_name} cred_id={credential_id_str[:16]}…"
        )
        log_security_event("WEBAUTHN_REGISTER_SUCCESS", uid=uid, details=f"device={resolved_device_name}")

        return True, "Passkey successfully registered!", {
            "id": cred_record.get("id"),
            "credential_id": credential_id_str,
            "device_name": resolved_device_name,
            "created_at": str(cred_record.get("created_at") or datetime.now()),
        }

    except Exception as e:
        safe_print(f"[WebAuthn Register Verification Error]: {e}")
        record_audit_log(
            "WEBAUTHN_REGISTER_FAILED",
            actor_uid=uid,
            actor_username=username,
            ip_address=client_ip,
            status="Failed",
            details=f"error={str(e)}"
        )
        return False, f"Passkey verification failed: {str(e)}", None


# ─── Passkey Authentication / Login ──────────────────────────────────────────────

def get_passkey_authentication_options(identifier: Optional[str] = None) -> Dict[str, Any]:
    """
    Generate WebAuthn assertion authentication options.
    If identifier is given, restrict allow_credentials to user's registered keys.
    If identifier is None, leave allow_credentials empty to trigger resident key / discoverable passkey modal.
    """
    allowed_credentials = None
    target_uid = None

    if identifier and identifier.strip():
        from opperation import get_users
        clean_id = identifier.strip()
        user_records = get_users(clean_id)
        if user_records and len(user_records) > 0:
            target_uid = user_records[0]["uid"]
            cred_rows = execute_query("SELECT credential_id FROM webauthn_credentials WHERE uid = %s", (target_uid,))
            if isinstance(cred_rows, list) and len(cred_rows) > 0:
                allowed_credentials = []
                for cr in cred_rows:
                    cid_str = cr.get("credential_id")
                    if cid_str:
                        try:
                            allowed_credentials.append(
                                PublicKeyCredentialDescriptor(
                                    id=base64url_to_bytes(cid_str),
                                    type=PublicKeyCredentialType.PUBLIC_KEY,
                                )
                            )
                        except Exception:
                            pass

    challenge_bytes, challenge_str = create_webauthn_challenge(uid=target_uid, challenge_type="authentication")

    options = generate_authentication_options(
        rp_id=get_rp_id(),
        challenge=challenge_bytes,
        allow_credentials=allowed_credentials,
        user_verification=UserVerificationRequirement.PREFERRED,
    )

    return json.loads(options_to_json(options))


def verify_passkey_authentication(credential_payload: Dict[str, Any], client_ip: str = "127.0.0.1") -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    """
    Verify browser assertion response against stored public key, update sign counter, and resolve user.
    """
    cred_id_raw = credential_payload.get("id") or credential_payload.get("rawId")
    if not cred_id_raw:
        return False, "Missing credential ID in WebAuthn response", None

    # Standardize credential ID string
    credential_id_str = str(cred_id_raw).strip()

    # Query registered credential
    cred_rows = execute_query(
        """SELECT id, uid, credential_id, public_key, sign_count, device_name
           FROM webauthn_credentials
           WHERE credential_id = %s
           LIMIT 1""",
        (credential_id_str,)
    )

    if not isinstance(cred_rows, list) or len(cred_rows) == 0:
        record_audit_log(
            "WEBAUTHN_LOGIN_FAILED",
            ip_address=client_ip,
            status="Failed",
            details="Unrecognized passkey credential ID"
        )
        return False, "This passkey is not recognized or has been removed from VaultAuth.", None

    cred_record = cred_rows[0]
    uid = cred_record["uid"]

    # Verify user is active
    user_rows = execute_query("SELECT uid, username, email, full_name, is_active, role FROM users WHERE uid = %s", (uid,))
    if not isinstance(user_rows, list) or len(user_rows) == 0:
        return False, "User account not found.", None

    user = user_rows[0]
    if user.get("is_active") is False:
        record_audit_log(
            "WEBAUTHN_LOGIN_BLOCKED",
            actor_uid=uid,
            actor_username=user.get("username"),
            ip_address=client_ip,
            status="Blocked",
            details="User account is deactivated"
        )
        return False, "Your account has been deactivated. Please contact your administrator.", None

    # Extract client challenge string from clientDataJSON
    client_challenge_str = None
    try:
        client_data_raw = credential_payload.get("response", {}).get("clientDataJSON", "")
        if client_data_raw:
            client_data_json = json.loads(base64url_to_bytes(client_data_raw).decode("utf-8"))
            client_challenge_str = client_data_json.get("challenge")
    except Exception as e:
        safe_print(f"[WebAuthn clientDataJSON Parse Warning]: {e}")

    # Consume matching challenge
    expected_challenge_bytes = consume_webauthn_challenge(
        challenge_str=client_challenge_str,
        expected_type="authentication",
        uid=None
    )

    if not expected_challenge_bytes:
        # Fallback: check any pending auth challenge
        now = datetime.now()
        fallback_rows = execute_query(
            "SELECT id, challenge_str, challenge_bytes FROM webauthn_challenges WHERE challenge_type = 'authentication' AND expires_at >= %s ORDER BY id DESC LIMIT 1",
            (now,)
        )
        if isinstance(fallback_rows, list) and len(fallback_rows) > 0:
            rec = fallback_rows[0]
            execute_query("DELETE FROM webauthn_challenges WHERE id = %s", (rec["id"],))
            raw_b = rec["challenge_bytes"]
            expected_challenge_bytes = bytes(raw_b) if isinstance(raw_b, (bytes, bytearray, memoryview)) else base64url_to_bytes(rec["challenge_str"])

    if not expected_challenge_bytes:
        record_audit_log(
            "WEBAUTHN_LOGIN_FAILED",
            actor_uid=uid,
            actor_username=user.get("username"),
            ip_address=client_ip,
            status="Failed",
            details="Expired or consumed authentication challenge"
        )
        return False, "Authentication challenge has expired. Please try signing in again.", None

    stored_public_key = cred_record["public_key"]
    if isinstance(stored_public_key, memoryview):
        stored_public_key = bytes(stored_public_key)

    stored_sign_count = cred_record.get("sign_count", 0)

    try:
        verified_auth = verify_authentication_response(
            credential=credential_payload,
            expected_challenge=expected_challenge_bytes,
            expected_rp_id=get_rp_id(),
            expected_origin=get_expected_origins(),
            credential_public_key=stored_public_key,
            credential_current_sign_count=stored_sign_count,
            require_user_verification=False,
        )

        # Update sign count and last used timestamp
        new_sign_count = verified_auth.new_sign_count or stored_sign_count
        execute_query(
            "UPDATE webauthn_credentials SET sign_count = %s, last_used_at = NOW() WHERE id = %s",
            (new_sign_count, cred_record["id"])
        )

        record_audit_log(
            "WEBAUTHN_LOGIN_SUCCESS",
            actor_uid=uid,
            actor_username=user.get("username"),
            ip_address=client_ip,
            status="Success",
            details=f"device={cred_record.get('device_name')} cred_id={credential_id_str[:16]}…"
        )
        log_security_event("WEBAUTHN_LOGIN_SUCCESS", uid=uid, details=f"cred_id={credential_id_str[:16]}")

        return True, "Passkey authentication successful!", user

    except Exception as e:
        safe_print(f"[WebAuthn Auth Verification Error]: {e}")
        record_audit_log(
            "WEBAUTHN_LOGIN_FAILED",
            actor_uid=uid,
            actor_username=user.get("username"),
            ip_address=client_ip,
            status="Failed",
            details=f"error={str(e)}"
        )
        return False, f"Passkey authentication failed: {str(e)}", None


# ─── Credential Management ───────────────────────────────────────────────────────

def get_user_passkeys(uid: int) -> List[Dict[str, Any]]:
    """Retrieve all registered passkeys for an employee."""
    from api.dashboard import format_relative_timestamp
    query = """
    SELECT id, credential_id, device_name, transports, aaguid, created_at, last_used_at
    FROM webauthn_credentials
    WHERE uid = %s
    ORDER BY created_at DESC
    """
    rows = execute_query(query, (uid,))
    results = []

    if isinstance(rows, list):
        for r in rows:
            cid = r.get("credential_id") or ""
            masked_cid = f"{cid[:8]}…{cid[-6:]}" if len(cid) > 16 else cid
            results.append({
                "id": r["id"],
                "credential_id_masked": masked_cid,
                "device_name": r.get("device_name") or "Passkey",
                "transports": r.get("transports") or "internal",
                "created_at": format_relative_timestamp(r.get("created_at")),
                "last_used_at": format_relative_timestamp(r.get("last_used_at")) if r.get("last_used_at") else "Never",
            })

    return results


def delete_user_passkey(uid: int, cred_id: int, client_ip: str = "127.0.0.1") -> Tuple[bool, str]:
    """Delete a user's passkey credential, strictly verifying ownership."""
    # Lookup to confirm ownership
    check_rows = execute_query(
        "SELECT id, device_name, credential_id FROM webauthn_credentials WHERE id = %s AND uid = %s",
        (cred_id, uid)
    )
    if not isinstance(check_rows, list) or len(check_rows) == 0:
        return False, "Passkey credential not found or access denied."

    cred_info = check_rows[0]
    execute_query("DELETE FROM webauthn_credentials WHERE id = %s AND uid = %s", (cred_id, uid))

    record_audit_log(
        "WEBAUTHN_CREDENTIAL_DELETED",
        actor_uid=uid,
        ip_address=client_ip,
        status="Success",
        details=f"deleted_id={cred_id} device={cred_info.get('device_name')}"
    )
    log_security_event("WEBAUTHN_CREDENTIAL_DELETED", uid=uid, details=f"cred_id={cred_id}")

    return True, "Passkey successfully removed."
