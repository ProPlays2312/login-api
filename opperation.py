from dotenv import load_dotenv
from datetime import datetime, timedelta
import secrets
from pathlib import Path
from werkzeug.security import generate_password_hash, check_password_hash

from api.db import execute_query
from api.utils import not_null
from api.token import generate_token
from api.mailer import send_otp_email

load_dotenv(dotenv_path=Path(__file__).resolve().parent / ".env")
load_dotenv()


def auth_user(login, password):
    query = "SELECT uid, username, email, password, is_active FROM users WHERE username = %s OR email = %s"
    try:
        result = execute_query(query, (login, login))
        if isinstance(result, list) and len(result) > 0:
            user = result[0]
            if user.get("is_active") is False:
                return None
            stored_pwd = user.get("password") or ""
            is_valid = False
            try:
                is_valid = check_password_hash(stored_pwd, str(password))
            except Exception:
                is_valid = False

            if not is_valid and stored_pwd == str(password):
                is_valid = True

            if is_valid:
                return {
                    "uid": user.get("uid"),
                    "username": user.get("username"),
                    "email": user.get("email")
                }
        return None
    except Exception as e:
        print(f"Error: {e}")
        return None


def register(data):
    if not isinstance(data, dict):
        return False
    username = not_null(data.get("username"))
    raw_password = not_null(data.get("password"))
    email = not_null(data.get("email"))
    if any(isinstance(val, str) and val.startswith("Error:") for val in [username, raw_password, email]):
        return False

    hashed_password = generate_password_hash(str(raw_password))
    c_date = datetime.now().strftime("%Y-%m-%d")
    explicit_uid = data.get("uid")

    if explicit_uid is not None:
        query = "INSERT INTO users (uid, username, password, email, c_date) VALUES (%s, %s, %s, %s, %s) RETURNING uid"
        params = (explicit_uid, username, hashed_password, email, c_date)
    else:
        query = "INSERT INTO users (username, password, email, c_date) VALUES (%s, %s, %s, %s) RETURNING uid"
        params = (username, hashed_password, email, c_date)

    try:
        result = execute_query(query, params)
        if isinstance(result, str) and result.startswith("Error:"):
            raise Exception(result)

        if isinstance(result, list) and len(result) > 0 and isinstance(result[0], dict):
            created_uid = result[0].get("uid", explicit_uid or 0)
        else:
            created_uid = explicit_uid or 0

        token_res = generate_token(username, created_uid)
        token = token_res[0] if isinstance(token_res, tuple) else token_res

        query2 = "INSERT INTO tokens (uid, md5, cr_date) VALUES (%s, %s, %s)"
        result2 = execute_query(query2, (created_uid, token, c_date))
        if isinstance(result2, str) and result2.startswith("Error:"):
            raise Exception(result2)

        return True
    except Exception as e:
        print(f"Error: {e}")
        return False


def get_users(data=None):
    if isinstance(data, int):
        query = "SELECT uid, username, email, is_active FROM users WHERE uid = %s"
        params = (data,)
    elif data is None:
        query = "SELECT uid, username, email, is_active FROM users"
        params = None
    elif isinstance(data, str):
        query = "SELECT uid, username, email, is_active FROM users WHERE username = %s OR email = %s"
        params = (data, data)
    else:
        return None
    try:
        result = execute_query(query, params) if params is not None else execute_query(query)
        if isinstance(result, list):
            if data is not None and len(result) == 0:
                return None
            return result
        return None
    except Exception as e:
        print(f"Error: {e}")
        return None


def create_otp(identifier, expires_in_seconds=300):
    if not identifier:
        return None, "Identifier is required"

    user_records = get_users(str(identifier).strip())
    if not user_records or len(user_records) == 0:
        return None, "User not found"

    user = user_records[0]
    if user.get("is_active") is False:
        return None, "Account is deactivated"

    uid = user.get("uid")
    email = user.get("email")
    now = datetime.now()

    # Rate Limiting: Maximum 5 OTP requests per 15 minutes
    try:
        window_start = now - timedelta(minutes=15)
        rate_query = "SELECT COUNT(*) as otp_count FROM otps WHERE uid = %s AND created_at >= %s"
        rate_res = execute_query(rate_query, (uid, window_start))
        if isinstance(rate_res, list) and len(rate_res) > 0:
            count = rate_res[0].get("otp_count") or 0
            if count >= 5:
                return {
                    "rate_limited": True,
                    "retry_after": 900
                }, "Rate limit exceeded. Please wait 15 minutes before requesting another OTP."
    except Exception as e:
        print(f"[OTP Rate Check Notice]: {e}")

    # Cooldown Check: 60-second cooldown between consecutive OTP requests
    try:
        cooldown_query = "SELECT created_at FROM otps WHERE uid = %s ORDER BY id DESC LIMIT 1"
        cooldown_res = execute_query(cooldown_query, (uid,))
        if isinstance(cooldown_res, list) and len(cooldown_res) > 0:
            last_created = cooldown_res[0].get("created_at")
            if last_created:
                if isinstance(last_created, str):
                    try:
                        last_created = datetime.fromisoformat(last_created)
                    except Exception:
                        pass
                if isinstance(last_created, datetime):
                    elapsed = (now - last_created).total_seconds()
                    if elapsed < 60:
                        remaining = max(1, int(60 - elapsed))
                        return {
                            "cooldown_remaining": remaining
                        }, f"Please wait {remaining} seconds before requesting a new OTP."
    except Exception as e:
        print(f"[OTP Cooldown Check Notice]: {e}")

    otp_code = f"{secrets.randbelow(900000) + 100000}"
    expires_at = now + timedelta(seconds=expires_in_seconds)

    query = """
    INSERT INTO otps (uid, email, otp_code, created_at, expires_at, used)
    VALUES (%s, %s, %s, %s, %s, FALSE)
    """
    params = (uid, email, otp_code, now, expires_at)
    res = execute_query(query, params)
    if isinstance(res, str) and res.startswith("Error:"):
        return None, res

    # Send real email via Gmail SMTP
    email_sent, email_err = send_otp_email(email, otp_code, user.get("username"))
    if not email_sent:
        try:
            execute_query("DELETE FROM otps WHERE uid = %s AND otp_code = %s", (uid, otp_code))
        except Exception:
            pass

    return {
        "otp": otp_code,
        "user": user,
        "email": email,
        "expires_in": expires_in_seconds,
        "cooldown": 60,
        "email_sent": email_sent,
        "email_err": email_err
    }, None


def verify_otp(identifier, otp_code):
    if not identifier or not otp_code:
        return None, "Identifier and OTP code are required"

    user_records = get_users(str(identifier).strip())
    if not user_records or len(user_records) == 0:
        return None, "User not found"

    user = user_records[0]
    if user.get("is_active") is False:
        return None, "Account is deactivated"

    uid = user.get("uid")
    code = str(otp_code).strip()

    now = datetime.now()
    query = """
    SELECT id, uid, email, otp_code, expires_at
    FROM otps
    WHERE uid = %s AND otp_code = %s AND used = FALSE AND expires_at >= %s
    ORDER BY id DESC
    LIMIT 1
    """
    params = (uid, code, now)
    res = execute_query(query, params)

    if not isinstance(res, list) or len(res) == 0:
        return None, "Invalid or expired OTP"

    otp_record = res[0]
    otp_id = otp_record.get("id")

    # Invalidate this OTP and mark as used (single-use)
    update_query = "UPDATE otps SET used = TRUE WHERE id = %s"
    execute_query(update_query, (otp_id,))

    return user, None
