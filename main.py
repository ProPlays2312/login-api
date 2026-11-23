from flask import Flask, request, jsonify, session
from flask_cors import CORS
import json
import os
from pathlib import Path
from dotenv import load_dotenv

from opperation import get_users, register, auth_user, create_otp, verify_otp
from api.token import generate_token, session_token, verify_token
from api.utils import safe_print
from api.auth_middleware import require_auth
from api.security import (
    rate_limit,
    validate_password_strength,
    validate_email,
    validate_username,
    sanitize_string,
    add_security_headers,
    log_security_event,
)
from api.rbac import require_role, require_admin, get_user_role, is_admin, ROLES, VALID_ROLES
from api.db import execute_query
from api.admin_db import init_admin_db
from api.admin import (
    get_admin_dashboard_stats,
    get_all_users_admin,
    admin_create_user,
    admin_update_user,
    admin_toggle_user_status,
    admin_delete_user,
    get_admin_all_sessions,
    admin_revoke_session,
    admin_revoke_all_user_sessions,
    get_admin_login_activity,
    get_audit_logs,
    get_admin_settings,
    update_admin_settings,
    get_roles_overview,
    record_audit_log,
)
from api.dashboard import (
    get_dashboard_overview,
    get_recent_login_activity,
    get_active_sessions,
    get_active_sessions_endpoint_data,
    revoke_session,
    revoke_other_sessions,
    get_connected_applications,
    disconnect_application,
    get_security_checklist,
    calculate_security_score,
    get_user_profile,
    update_security_settings,
    record_login_activity,
    create_user_session,
    ensure_default_user_dashboard_data,
)
from api.webauthn_service import (
    get_passkey_registration_options,
    verify_and_save_passkey_registration,
    get_passkey_authentication_options,
    verify_passkey_authentication,
    get_user_passkeys,
    delete_user_passkey,
)
from flask import g

load_dotenv(dotenv_path=Path(__file__).resolve().parent / ".env")
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY") or os.getenv("TOKEN_SECRET", "vault-auth-secret-key-change-in-production")
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024  # Enforce 1 MB request body limit

cors_origins_env = os.getenv("CORS_ORIGINS", "")
if cors_origins_env:
    allowed_origins = [o.strip() for o in cors_origins_env.split(",") if o.strip()]
else:
    allowed_origins = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5000",
        "http://127.0.0.1:5000",
        "http://localhost:5500",
        "http://127.0.0.1:5500",
    ]

CORS(app, resources={r"/*": {"origins": allowed_origins}}, supports_credentials=True)


@app.after_request
def apply_security_headers(response):
    """Enforce defense-in-depth HTTP security headers on all responses."""
    return add_security_headers(response)


@app.route("/", methods=["GET"])
@app.route("/api", methods=["GET"])
@app.route("/api/health", methods=["GET"])
@app.route("/health", methods=["GET"])
def health_check():
    return jsonify({
        "status": "ok",
        "service": "Vault Auth Backend",
        "version": "1.0.0",
        "docs": "/docs",
        "openapi": "/openapi.json"
    }), 200


@app.route("/api/users", methods=["GET"])
@require_auth
def users():
    try:
        user_list = get_users(None)
        if user_list is not None:
            return jsonify(user_list)
        else:
            return jsonify({"message": "Error getting users"}), 500
    except Exception as e:
        return jsonify({"message": f"Error: {e}"}), 500


@app.route("/api/users/<int:uid>", methods=["GET"])
@require_auth
def users_id(uid):
    try:
        user = get_users(uid)
        if user is not None:
            return jsonify(user)
        else:
            return jsonify({"message": "Error: User not found"}), 404
    except Exception as e:
        return jsonify({"message": f"Error: {e}"}), 500


@app.route("/api/users/<string:id>", methods=["GET"])
@require_auth
def username(id):
    try:
        user = get_users(id)
        if user is not None:
            return jsonify(user)
        else:
            return jsonify({"message": "Error: User not found"}), 404
    except Exception as e:
        return jsonify({"message": f"Error: {e}"}), 500


@app.route("/api/register", methods=["POST"])
@rate_limit(max_requests=10, window_seconds=60, key_prefix="register")
def create_user():
    data = request.get_json()
    if data is None:
        return jsonify({"message": "Data is null"}), 400

    username = data.get("username")
    password = data.get("password")
    email = data.get("email")

    if not username or not password or not email:
        return jsonify({"message": "Username, email, and password are required"}), 400

    # Password Policy: Minimum 8 characters, non-empty, reject trivial passwords
    is_valid, pwd_strength, pwd_errors = validate_password_strength(password)
    if not is_valid:
        log_security_event("REGISTRATION_REJECTED", details=f"reason=weak_password username={username}")
        return jsonify({
            "message": "Password does not meet security requirements.",
            "errors": pwd_errors
        }), 400

    # Validate email
    try:
        data["email"] = validate_email(email)
    except ValueError as ve:
        return jsonify({"message": f"Invalid email: {ve}"}), 400

    # Validate username
    try:
        data["username"] = validate_username(username)
    except ValueError as ve:
        return jsonify({"message": f"Invalid username: {ve}"}), 400

    # Sanitize optional full_name / phone if provided
    raw_name = data.get("fullName") or data.get("full_name") or data.get("name")
    if raw_name:
        try:
            data["full_name"] = sanitize_string(raw_name, max_length=100)
        except ValueError as ve:
            return jsonify({"message": f"Invalid name: {ve}"}), 400

    phone = data.get("phone")
    if phone:
        try:
            data["phone"] = sanitize_string(phone, max_length=20)
        except ValueError as ve:
            return jsonify({"message": f"Invalid phone: {ve}"}), 400

    try:
        result = register(data)
        if result is False:
            log_security_event("REGISTRATION_FAILED", details=f"username={username}")
            return jsonify({"message": "Registration failed. Username or email may already be taken."}), 400
        log_security_event("REGISTRATION_SUCCESS", details=f"username={username}")
        return jsonify(result), 200
    except Exception as e:
        safe_print(f"Registration error: {e}")
        return jsonify({"message": f"Error: {e}"}), 500


@app.route("/api/login", methods=["POST"])
@rate_limit(max_requests=15, window_seconds=60, key_prefix="login")
def login():
    data = request.get_json()
    if data is None:
        return jsonify({"message": "Data is null"}), 400

    login_identifier = data.get("login") or data.get("username")
    password = data.get("password")
    if not login_identifier or not password:
        return jsonify({"message": "User not found"}), 404

    try:
        result = auth_user(login_identifier, password)
        if not result or (isinstance(result, str) and result.startswith("Error")):
            try:
                user_rec = get_users(login_identifier)
                if user_rec and len(user_rec) > 0:
                    record_login_activity(user_rec[0]["uid"], request, status="Failed")
            except Exception:
                pass
            log_security_event("LOGIN_FAILED", details=f"identifier={login_identifier}")
            return jsonify({"message": "User not found"}), 404
    except Exception as e:
        safe_print(f"Login error: {e}")
        return jsonify({"message": f"Error: {e}"}), 500

    try:
        if isinstance(result, dict):
            uid = result.get("uid") or result.get("id") or 0
            user = result.get("username") or result.get("user") or login_identifier
        else:
            user_record = get_users(login_identifier)
            if user_record and len(user_record) > 0 and isinstance(user_record[0], dict):
                uid = user_record[0].get("uid") or user_record[0].get("id") or 0
                user = user_record[0].get("username") or user_record[0].get("user") or login_identifier
            else:
                uid = 0
                user = login_identifier

        token_res = generate_token({"username": user, "uid": uid})
        raw_token = token_res[0] if isinstance(token_res, tuple) else token_res
        s_token = session_token(raw_token)
        session["token"] = s_token

        # Record successful session & activity for dashboard
        try:
            if uid:
                record_login_activity(uid, request, status="Success")
                create_user_session(uid, s_token, request)
                ensure_default_user_dashboard_data(uid, {"username": user, "uid": uid})
        except Exception as e:
            safe_print(f"Session tracking notice: {e}")

        log_security_event("LOGIN_SUCCESS", uid=uid, details=f"username={user}")
        response = jsonify({"message": "Login successful", "token": s_token})
        response.set_cookie(
            "token",
            s_token,
            httponly=True,
            samesite="Lax",
            max_age=int(os.getenv("TOKEN_EXPIRATION", "3600") or 3600)
        )
        return response, 200
    except Exception as e:
        safe_print(f"Login token error: {e}")
        return jsonify({"message": f"Error: {e}"}), 500


def mask_email(email):
    if not email or "@" not in email:
        return email
    local, domain = email.split("@", 1)
    if len(local) <= 2:
        masked_local = local[0] + "*"
    else:
        masked_local = local[0] + "*" * (len(local) - 2) + local[-1]
    return f"{masked_local}@{domain}"


@app.route("/api/otp/send", methods=["POST"])
@app.route("/api/login/otp/send", methods=["POST"])
@rate_limit(max_requests=10, window_seconds=60, key_prefix="otp_send")
def send_otp():
    data = request.get_json() if request.is_json else {}
    if not data:
        return jsonify({"message": "Request body cannot be empty"}), 400

    identifier = (
        data.get("identifier")
        or data.get("login")
        or data.get("username")
        or data.get("email")
    )

    if not identifier:
        return jsonify({"message": "Identifier (username or email) is required"}), 400

    otp_info, err = create_otp(identifier)
    if err == "User not found":
        log_security_event("OTP_SEND_FAILED", details=f"identifier={identifier} reason=not_found")
        return jsonify({"message": "User not found"}), 404
    elif err == "Account is deactivated":
        log_security_event("OTP_SEND_BLOCKED", details=f"identifier={identifier} reason=deactivated")
        return jsonify({"message": "Account is deactivated. Please contact your administrator."}), 403
    elif isinstance(otp_info, dict) and otp_info.get("rate_limited"):
        return jsonify({
            "message": err,
            "retry_after": otp_info.get("retry_after", 900)
        }), 429
    elif isinstance(otp_info, dict) and otp_info.get("cooldown_remaining"):
        return jsonify({
            "message": err,
            "retry_after": otp_info.get("cooldown_remaining"),
            "cooldown": otp_info.get("cooldown_remaining")
        }), 429
    elif err:
        return jsonify({"message": f"Error: {err}"}), 500

    # If real email dispatch failed (e.g. Plunk API error)
    if otp_info.get("email_sent") is False:
        err_detail = otp_info.get("email_err") or "Email could not be delivered"
        log_security_event("OTP_DELIVERY_FAILED", details=f"identifier={identifier} err={err_detail}")
        return jsonify({
            "message": f"Email delivery failed: {err_detail}.",
            "error": err_detail,
            "email_sent": False
        }), 500

    user_email = otp_info["email"]
    masked = mask_email(user_email)

    response_data = {
        "message": f"OTP sent to {masked}",
        "identifier": identifier,
        "email_masked": masked,
        "expires_in": otp_info.get("expires_in", 300),
        "cooldown": otp_info.get("cooldown", 60),
        "email_sent": otp_info.get("email_sent", False)
    }

    log_security_event("OTP_SENT_SUCCESS", details=f"identifier={identifier} email={masked}")
    return jsonify(response_data), 200


@app.route("/api/otp/verify", methods=["POST"])
@app.route("/api/login/otp/verify", methods=["POST"])
@app.route("/api/login/otp", methods=["POST"])
@rate_limit(max_requests=15, window_seconds=60, key_prefix="otp_verify")
def verify_otp_endpoint():
    data = request.get_json() if request.is_json else {}
    if not data:
        return jsonify({"message": "Request body cannot be empty"}), 400

    identifier = (
        data.get("identifier")
        or data.get("login")
        or data.get("username")
        or data.get("email")
    )
    otp_code = (
        data.get("otp")
        or data.get("code")
        or data.get("otp_code")
    )

    if not identifier or not otp_code:
        return jsonify({"message": "Both identifier and OTP code are required"}), 400

    user, err = verify_otp(identifier, otp_code)
    if err == "User not found":
        log_security_event("OTP_VERIFY_FAILED", details=f"identifier={identifier} reason=not_found")
        return jsonify({"message": "User not found"}), 404
    elif err == "Account is deactivated":
        log_security_event("OTP_VERIFY_BLOCKED", details=f"identifier={identifier} reason=deactivated")
        return jsonify({"message": "Account is deactivated"}), 403
    elif err or not user:
        err_msg = err if (isinstance(err, str) and err) else "Invalid or expired OTP"
        log_security_event("OTP_VERIFY_FAILED", details=f"identifier={identifier} reason={err_msg}")
        return jsonify({"message": err_msg}), 401

    try:
        uid = user.get("uid") or 0
        username = user.get("username") or identifier
        token_res = generate_token({"username": username, "uid": uid})
        raw_token = token_res[0] if isinstance(token_res, tuple) else token_res
        s_token = session_token(raw_token)
        session["token"] = s_token

        # Record verified OTP session & activity for dashboard
        try:
            if uid:
                record_login_activity(uid, request, status="Success")
                create_user_session(uid, s_token, request)
                ensure_default_user_dashboard_data(uid, user)
        except Exception as e:
            safe_print(f"OTP session tracking notice: {e}")

        log_security_event("OTP_VERIFY_SUCCESS", uid=uid, details=f"username={username}")
        response = jsonify({
            "message": "OTP login successful",
            "token": s_token,
            "user": {
                "uid": uid,
                "username": username,
                "email": user.get("email")
            }
        })
        response.set_cookie(
            "token",
            s_token,
            httponly=True,
            samesite="Lax",
            max_age=int(os.getenv("TOKEN_EXPIRATION", "3600") or 3600)
        )
        return response, 200
    except Exception as e:
        safe_print(f"OTP token generation error: {e}")
        return jsonify({"message": f"Error: {e}"}), 500


@app.route("/api/verify", methods=["GET", "POST"])
def verify():
    auth_header = request.headers.get("Authorization")
    token = None
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ", 1)[1].strip()
    elif request.is_json and request.get_json():
        token = request.get_json().get("token")
    elif request.args.get("token"):
        token = request.args.get("token")
    else:
        token = session.get("token") or request.cookies.get("token")

    if not token:
        return jsonify({"valid": False, "message": "Invalid or expired token"}), 401

    token = str(token).strip()
    if not verify_token(token):
        return jsonify({"valid": False, "message": "Invalid or expired token"}), 401

    # Check if session has been revoked in active_sessions
    try:
        revoked_check = execute_query(
            "SELECT id FROM active_sessions WHERE session_token = %s AND is_active = FALSE LIMIT 1",
            (token,)
        )
        if isinstance(revoked_check, list) and len(revoked_check) > 0:
            return jsonify({"valid": False, "message": "Session has been revoked or logged out"}), 401
    except Exception as e:
        safe_print(f"[Verify Session Check]: {e}")

    return jsonify({"valid": True, "message": "Token is valid", "token": token}), 200


@app.route("/api/logout", methods=["POST"])
def logout():
    token = None
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ", 1)[1].strip()
    elif request.is_json and request.get_json():
        token = request.get_json().get("token")
    elif request.args.get("token"):
        token = request.args.get("token")
    else:
        token = session.get("token") or request.cookies.get("token")

    if token:
        try:
            execute_query(
                "UPDATE active_sessions SET is_active = FALSE, revoked_at = NOW() WHERE session_token = %s",
                (token,)
            )
            log_security_event("LOGOUT_SESSION_INVALIDATED", details="Session explicitly deactivated in DB")
        except Exception as e:
            try:
                execute_query(
                    "UPDATE active_sessions SET is_active = FALSE WHERE session_token = %s",
                    (token,)
                )
            except Exception:
                pass
            safe_print(f"[Logout Session Invalidation]: {e}")

    session.pop("token", None)
    response = jsonify({"message": "Logout successful"})
    response.set_cookie("token", "", expires=0)
    return response, 200


# ==============================================================================
# Role-Based Access Control (RBAC) & Enterprise Admin Endpoints
# ==============================================================================

@app.route("/api/user/role", methods=["GET"])
@require_auth
def get_current_user_role():
    """Retrieve the authenticated user's assigned role."""
    try:
        role = get_user_role(g.user["uid"])
        return jsonify({
            "uid": g.user["uid"],
            "username": g.user.get("username"),
            "role": role,
            "role_title": ROLES.get(role, "End User")
        }), 200
    except Exception as e:
        safe_print(f"[RBAC] get role error: {e}")
        return jsonify({"message": "Error retrieving role"}), 500


@app.route("/api/admin/dashboard/stats", methods=["GET"])
@require_auth
@require_admin
def admin_dashboard_stats():
    """Admin: aggregate stats for dashboard overview cards."""
    try:
        stats = get_admin_dashboard_stats()
        record_audit_log("ADMIN_STATS_VIEW", actor_uid=g.user["uid"],
                         actor_username=g.user.get("username"), ip_address=request.remote_addr)
        return jsonify(stats), 200
    except Exception as e:
        return jsonify({"message": f"Error: {e}"}), 500


@app.route("/api/admin/users", methods=["GET"])
@require_auth
@require_admin
def admin_list_users():
    """Enterprise Admin: retrieve employee user directory with roles and filters."""
    try:
        page_arg = request.args.get("page")
        search_arg = request.args.get("search")
        role_arg = request.args.get("role")
        status_arg = request.args.get("status")
        paginate_arg = request.args.get("paginate")

        # If pagination or filtering requested by Admin Dashboard
        if page_arg is not None or paginate_arg == "true" or search_arg or (role_arg and role_arg != "all") or (status_arg and status_arg != "all"):
            page = max(1, int(page_arg or 1))
            per_page = min(100, max(5, int(request.args.get("per_page", 20) or 20)))
            result = get_all_users_admin(search_arg, role_arg, status_arg, page, per_page)
            record_audit_log("ADMIN_DIRECTORY_ACCESSED", actor_uid=g.user["uid"],
                             actor_username=g.user.get("username"), ip_address=request.remote_addr)
            return jsonify(result), 200

        # Unpaginated list for backward compatibility with existing tests
        user_list = get_users(None)
        if user_list is None:
            return jsonify({"message": "Error getting users"}), 500

        sanitized_users = []
        for u in user_list:
            uid = u.get("uid")
            role = get_user_role(uid)
            sanitized_users.append({
                "uid": uid,
                "username": u.get("username"),
                "email": u.get("email"),
                "full_name": u.get("full_name") or u.get("username"),
                "is_active": u.get("is_active", True),
                "role": role,
                "role_title": ROLES.get(role, "End User")
            })
        log_security_event("ADMIN_DIRECTORY_ACCESSED", uid=g.user["uid"])
        return jsonify(sanitized_users), 200
    except Exception as e:
        safe_print(f"[Admin List Users]: {e}")
        return jsonify({"message": "Error retrieving users"}), 500


@app.route("/api/admin/users", methods=["POST"])
@require_auth
@require_admin
def admin_add_user():
    """Admin: create a new user."""
    try:
        data = request.get_json() or {}
        username = str(data.get("username", "")).strip()
        email = str(data.get("email", "")).strip()
        password = str(data.get("password", "")).strip()
        full_name = data.get("full_name") or data.get("fullName")
        phone = data.get("phone")
        role = data.get("role", "user")

        if not username or not email or not password:
            return jsonify({"success": False, "message": "username, email, and password are required"}), 400

        success, result = admin_create_user(username, email, password, full_name, phone, role)
        if success:
            record_audit_log("ADMIN_USER_CREATED", actor_uid=g.user["uid"],
                             actor_username=g.user.get("username"),
                             target_username=username, ip_address=request.remote_addr)
            log_security_event("ADMIN_USER_CREATED", uid=g.user["uid"], details=f"new_user={username}")
            return jsonify({"success": True, "message": "User created", "user": result}), 201
        return jsonify({"success": False, "message": result}), 400
    except Exception as e:
        return jsonify({"message": f"Error: {e}"}), 500


@app.route("/api/admin/users/<int:target_uid>", methods=["PUT"])
@require_auth
@require_admin
def admin_edit_user(target_uid):
    """Admin: update user fields."""
    try:
        data = request.get_json() or {}
        success, msg = admin_update_user(target_uid, data, g.user["uid"])
        if success:
            record_audit_log("ADMIN_USER_UPDATED", actor_uid=g.user["uid"],
                             actor_username=g.user.get("username"), target_uid=target_uid,
                             ip_address=request.remote_addr)
            log_security_event("ADMIN_USER_UPDATED", uid=g.user["uid"], details=f"target_uid={target_uid}")
        return jsonify({"success": success, "message": msg}), 200 if success else 400
    except Exception as e:
        return jsonify({"message": f"Error: {e}"}), 500


@app.route("/api/admin/users/<int:target_uid>/status", methods=["PUT"])
@require_auth
@require_admin
def admin_toggle_status(target_uid):
    """Admin: activate or deactivate a user."""
    try:
        data = request.get_json() or {}
        is_active = bool(data.get("is_active", True))

        # Prevent admin from deactivating themselves
        if target_uid == g.user["uid"] and not is_active:
            return jsonify({"success": False, "message": "Cannot deactivate your own account"}), 400

        success, msg = admin_toggle_user_status(target_uid, is_active, g.user["uid"])
        if success:
            action = "ADMIN_USER_ACTIVATED" if is_active else "ADMIN_USER_DEACTIVATED"
            record_audit_log(action, actor_uid=g.user["uid"], actor_username=g.user.get("username"),
                             target_uid=target_uid, ip_address=request.remote_addr)
            log_security_event(action, uid=g.user["uid"], details=f"target_uid={target_uid}")
        return jsonify({"success": success, "message": msg}), 200 if success else 404
    except Exception as e:
        return jsonify({"message": f"Error: {e}"}), 500


@app.route("/api/admin/users/<int:target_uid>", methods=["DELETE"])
@require_auth
@require_admin
def admin_remove_user(target_uid):
    """Admin: permanently delete a user."""
    try:
        # Prevent self-deletion
        if target_uid == g.user["uid"]:
            return jsonify({"success": False, "message": "Cannot delete your own account"}), 400

        success, msg = admin_delete_user(target_uid, g.user["uid"])
        if success:
            record_audit_log("ADMIN_USER_DELETED", actor_uid=g.user["uid"],
                             actor_username=g.user.get("username"), target_uid=target_uid,
                             ip_address=request.remote_addr, details=msg)
            log_security_event("ADMIN_USER_DELETED", uid=g.user["uid"], details=f"target_uid={target_uid}")
        return jsonify({"success": success, "message": msg}), 200 if success else 404
    except Exception as e:
        return jsonify({"message": f"Error: {e}"}), 500


@app.route("/api/admin/roles", methods=["GET"])
@require_auth
@require_admin
def admin_get_roles():
    """Admin: get roles and permissions overview."""
    try:
        result = get_roles_overview()
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"message": f"Error: {e}"}), 500


@app.route("/api/admin/sessions", methods=["GET"])
@require_auth
@require_admin
def admin_get_sessions():
    """Admin: list all sessions across all users."""
    try:
        search = request.args.get("search", "").strip() or None
        status_filter = request.args.get("status", "all")
        page = max(1, int(request.args.get("page", 1) or 1))
        per_page = min(100, max(5, int(request.args.get("per_page", 20) or 20)))
        result = get_admin_all_sessions(search, status_filter, page, per_page)
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"message": f"Error: {e}"}), 500


@app.route("/api/admin/sessions/<string:session_id>/revoke", methods=["POST"])
@require_auth
@require_admin
def admin_revoke_one_session(session_id):
    """Admin: revoke a specific session."""
    try:
        success, msg = admin_revoke_session(session_id, g.user["uid"])
        if success:
            record_audit_log("ADMIN_SESSION_REVOKED", actor_uid=g.user["uid"],
                             actor_username=g.user.get("username"),
                             details=f"session_id={session_id}", ip_address=request.remote_addr)
        return jsonify({"success": success, "message": msg}), 200 if success else 404
    except Exception as e:
        return jsonify({"message": f"Error: {e}"}), 500


@app.route("/api/admin/users/<int:target_uid>/sessions/revoke-all", methods=["POST"])
@require_auth
@require_admin
def admin_revoke_user_sessions(target_uid):
    """Admin: revoke all sessions for a specific user."""
    try:
        success, msg = admin_revoke_all_user_sessions(target_uid, g.user["uid"])
        record_audit_log("ADMIN_ALL_SESSIONS_REVOKED", actor_uid=g.user["uid"],
                         actor_username=g.user.get("username"), target_uid=target_uid,
                         ip_address=request.remote_addr)
        return jsonify({"success": success, "message": msg}), 200
    except Exception as e:
        return jsonify({"message": f"Error: {e}"}), 500


@app.route("/api/admin/login-activity", methods=["GET"])
@require_auth
@require_admin
def admin_get_login_activity():
    """Admin: list login activity across all users."""
    try:
        search = request.args.get("search", "").strip() or None
        status_filter = request.args.get("status", "all")
        date_from = request.args.get("date_from")
        date_to = request.args.get("date_to")
        page = max(1, int(request.args.get("page", 1) or 1))
        per_page = min(100, max(5, int(request.args.get("per_page", 25) or 25)))
        result = get_admin_login_activity(search, status_filter, date_from, date_to, page, per_page)
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"message": f"Error: {e}"}), 500


@app.route("/api/admin/audit-logs", methods=["GET"])
@require_auth
@require_admin
def admin_get_audit_logs():
    """Admin: list security audit logs."""
    try:
        search = request.args.get("search", "").strip() or None
        event_filter = request.args.get("event", "all")
        page = max(1, int(request.args.get("page", 1) or 1))
        per_page = min(100, max(5, int(request.args.get("per_page", 25) or 25)))
        result = get_audit_logs(search, event_filter, page, per_page)
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"message": f"Error: {e}"}), 500


@app.route("/api/admin/settings", methods=["GET"])
@require_auth
@require_admin
def admin_get_settings():
    """Admin: retrieve non-secret system settings."""
    try:
        settings = get_admin_settings()
        return jsonify(settings), 200
    except Exception as e:
        return jsonify({"message": f"Error: {e}"}), 500


@app.route("/api/admin/settings", methods=["PUT"])
@require_auth
@require_admin
def admin_update_settings():
    """Admin: update allowed system settings."""
    try:
        data = request.get_json() or {}
        success, msg = update_admin_settings(data, g.user["uid"])
        if success:
            record_audit_log("ADMIN_SETTINGS_UPDATED", actor_uid=g.user["uid"],
                             actor_username=g.user.get("username"), ip_address=request.remote_addr,
                             details=f"keys={list(data.keys())}")
        return jsonify({"success": success, "message": msg}), 200
    except Exception as e:
        return jsonify({"message": f"Error: {e}"}), 500


@app.route("/api/admin/users/<int:target_uid>/role", methods=["PUT"])
@require_auth
@require_admin
def admin_update_user_role(target_uid):
    """Enterprise Admin: update a target employee's role."""
    try:
        data = request.get_json() or {}
        new_role = str(data.get("role", "")).lower().strip()
        if new_role not in VALID_ROLES:
            return jsonify({
                "success": False,
                "message": f"Invalid role. Allowed roles are: {list(VALID_ROLES)}"
            }), 400

        target_user = get_users(target_uid)
        if not target_user:
            return jsonify({"success": False, "message": "Target user not found"}), 404

        # Prevent lockout: Cannot demote the last remaining admin
        if target_uid == g.user["uid"] and new_role != "admin":
            admin_count_res = execute_query("SELECT COUNT(*) as count FROM users WHERE role = 'admin'")
            admin_count = admin_count_res[0].get("count", 0) if (isinstance(admin_count_res, list) and len(admin_count_res) > 0 and isinstance(admin_count_res[0], dict)) else 1
            if admin_count <= 1:
                return jsonify({
                    "success": False,
                    "message": "Cannot demote the last remaining administrator."
                }), 400

        res = execute_query("UPDATE users SET role = %s WHERE uid = %s", (new_role, target_uid))
        if isinstance(res, str) and res.startswith("Error:"):
            return jsonify({"message": f"Database error: {res}"}), 500

        # Synchronize role in user_security_settings as well
        execute_query("UPDATE user_security_settings SET role = %s WHERE uid = %s", (ROLES.get(new_role, "End user"), target_uid))
        log_security_event(
            "ADMIN_ROLE_CHANGE",
            uid=g.user["uid"],
            details=f"target_uid={target_uid} new_role={new_role}"
        )
        return jsonify({
            "success": True,
            "message": f"User role successfully updated to '{new_role}'",
            "uid": target_uid,
            "role": new_role
        }), 200
    except Exception as e:
        safe_print(f"[Admin Set Role]: {e}")
        return jsonify({"message": "Error updating user role"}), 500


@app.route("/openapi.json", methods=["GET"])
@app.route("/api/openapi.json", methods=["GET"])
def openapi_spec():
    spec_path = Path(__file__).resolve().parent / "openapi.json"
    if spec_path.exists():
        with open(spec_path, "r", encoding="utf-8") as f:
            return jsonify(json.load(f))
    return jsonify({"message": "OpenAPI specification not found"}), 404


@app.route("/docs", methods=["GET"])
@app.route("/api/docs", methods=["GET"])
def swagger_ui():
    html_content = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Vault Auth API Documentation</title>
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css" />
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
  <script>
    window.onload = () => {
      window.ui = SwaggerUIBundle({
        url: '/openapi.json',
        dom_id: '#swagger-ui',
      });
    };
  </script>
</body>
</html>"""
    return html_content, 200, {"Content-Type": "text/html"}


# ==============================================================================
# Dashboard API Endpoints (Protected by @require_auth)
# ==============================================================================

@app.route("/api/dashboard/overview", methods=["GET"])
@require_auth
def dashboard_overview():
    try:
        ensure_default_user_dashboard_data(g.user["uid"], g.user)
        data = get_dashboard_overview(g.user["uid"], g.token)
        return jsonify(data), 200
    except Exception as e:
        safe_print(f"Overview error: {e}")
        return jsonify({"message": f"Error retrieving overview: {e}"}), 500


@app.route("/api/dashboard/login-activity", methods=["GET"])
@require_auth
def dashboard_login_activity():
    try:
        limit = int(request.args.get("limit", 10))
        status_filter = request.args.get("status")
        activities = get_recent_login_activity(g.user["uid"], limit=limit, filter_status=status_filter)
        return jsonify(activities), 200
    except Exception as e:
        safe_print(f"Login activity error: {e}")
        return jsonify({"message": f"Error retrieving login activity: {e}"}), 500


@app.route("/api/sessions", methods=["GET"])
@require_auth
def list_sessions():
    try:
        sessions = get_active_sessions(g.user["uid"], g.token)
        return jsonify(sessions), 200
    except Exception as e:
        safe_print(f"Sessions error: {e}")
        return jsonify({"message": f"Error retrieving sessions: {e}"}), 500


@app.route("/api/sessions/active", methods=["GET"])
@require_auth
def active_sessions_summary():
    """Return strictly verified active and valid device sessions for the authenticated user."""
    try:
        data = get_active_sessions_endpoint_data(g.user["uid"], g.token)
        return jsonify(data), 200
    except Exception as e:
        safe_print(f"Active sessions error: {e}")
        return jsonify({"success": False, "message": f"Error retrieving active sessions: {e}"}), 500


@app.route("/api/sessions/<string:session_id>", methods=["DELETE"])
@require_auth
def delete_session(session_id):
    try:
        success, msg = revoke_session(g.user["uid"], session_id)
        if success:
            return jsonify({"success": True, "message": msg}), 200
        return jsonify({"success": False, "message": msg}), 404
    except Exception as e:
        safe_print(f"Revoke session error: {e}")
        return jsonify({"message": f"Error revoking session: {e}"}), 500


@app.route("/api/sessions/revoke-others", methods=["POST"])
@require_auth
def revoke_others():
    try:
        success, msg = revoke_other_sessions(g.user["uid"], g.token)
        return jsonify({"success": True, "message": msg}), 200
    except Exception as e:
        safe_print(f"Revoke others error: {e}")
        return jsonify({"message": f"Error revoking sessions: {e}"}), 500


@app.route("/api/connected-apps", methods=["GET"])
@require_auth
def list_connected_apps():
    try:
        ensure_default_user_dashboard_data(g.user["uid"], g.user)
        apps = get_connected_applications(g.user["uid"])
        return jsonify(apps), 200
    except Exception as e:
        safe_print(f"Connected apps error: {e}")
        return jsonify({"message": f"Error retrieving connected apps: {e}"}), 500


@app.route("/api/connected-apps/<int:app_id>", methods=["DELETE"])
@require_auth
def delete_connected_app(app_id):
    try:
        success, msg = disconnect_application(g.user["uid"], app_id)
        if success:
            return jsonify({"success": True, "message": msg}), 200
        return jsonify({"success": False, "message": msg}), 404
    except Exception as e:
        safe_print(f"Disconnect app error: {e}")
        return jsonify({"message": f"Error disconnecting app: {e}"}), 500


@app.route("/api/security/checklist", methods=["GET"])
@require_auth
def security_checklist():
    try:
        ensure_default_user_dashboard_data(g.user["uid"], g.user)
        checklist = get_security_checklist(g.user["uid"])
        return jsonify(checklist), 200
    except Exception as e:
        safe_print(f"Security checklist error: {e}")
        return jsonify({"message": f"Error retrieving security checklist: {e}"}), 500


@app.route("/api/security/score", methods=["GET"])
@require_auth
def security_score():
    try:
        ensure_default_user_dashboard_data(g.user["uid"], g.user)
        score_data = calculate_security_score(g.user["uid"])
        return jsonify(score_data), 200
    except Exception as e:
        safe_print(f"Security score error: {e}")
        return jsonify({"message": f"Error calculating security score: {e}"}), 500


@app.route("/api/security/settings", methods=["PUT"])
@require_auth
def modify_security_settings():
    try:
        ensure_default_user_dashboard_data(g.user["uid"], g.user)
        data = request.get_json() if request.is_json else {}
        success, msg = update_security_settings(g.user["uid"], data)
        return jsonify({"success": success, "message": msg}), 200
    except Exception as e:
        safe_print(f"Update security error: {e}")
        return jsonify({"message": f"Error updating security settings: {e}"}), 500


@app.route("/api/user/profile", methods=["GET"])
@require_auth
def user_profile():
    try:
        ensure_default_user_dashboard_data(g.user["uid"], g.user)
        profile = get_user_profile(g.user["uid"])
        if profile:
            return jsonify(profile), 200
        return jsonify({"message": "Profile not found"}), 404
    except Exception as e:
        safe_print(f"User profile error: {e}")
        return jsonify({"message": f"Error retrieving profile: {e}"}), 500


# ─── WebAuthn / FIDO2 Passkey Endpoints ──────────────────────────────────────

@app.route("/api/webauthn/register/options", methods=["POST"])
@require_auth
def webauthn_register_options():
    """Generate registration challenge and credential creation options for authenticated user."""
    try:
        ensure_default_user_dashboard_data(g.user["uid"], g.user)
        options = get_passkey_registration_options(g.user)
        return jsonify(options), 200
    except Exception as e:
        safe_print(f"WebAuthn register options error: {e}")
        return jsonify({"message": f"Failed to generate passkey options: {e}"}), 500


@app.route("/api/webauthn/register/verify", methods=["POST"])
@require_auth
def webauthn_register_verify():
    """Verify and persist newly registered passkey credential."""
    try:
        ensure_default_user_dashboard_data(g.user["uid"], g.user)
        data = request.get_json() if request.is_json else {}
        if not data:
            return jsonify({"message": "Invalid or missing WebAuthn registration payload"}), 400

        # Support both wrapped { credential: {...}, deviceName: ... } and direct credential object
        if "credential" in data and isinstance(data["credential"], dict):
            credential_payload = data["credential"]
            device_name = data.get("deviceName") or data.get("device_name")
        else:
            credential_payload = data
            device_name = data.get("deviceName") or data.get("device_name")

        client_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "127.0.0.1").split(",")[0].strip()
        success, msg, cred_info = verify_and_save_passkey_registration(
            user=g.user,
            credential_payload=credential_payload,
            device_name=device_name,
            client_ip=client_ip
        )

        if not success:
            return jsonify({"success": False, "message": msg}), 400

        return jsonify({
            "success": True,
            "message": msg,
            "credential": cred_info
        }), 200
    except Exception as e:
        safe_print(f"WebAuthn register verify error: {e}")
        return jsonify({"success": False, "message": f"Server error verifying passkey: {e}"}), 500


@app.route("/api/webauthn/login/options", methods=["POST"])
@rate_limit(max_requests=30, window_seconds=60, key_prefix="webauthn_login_options")
def webauthn_login_options():
    """Generate authentication options for Passkey login."""
    try:
        data = request.get_json(silent=True) or {}
        identifier = (
            data.get("identifier")
            or data.get("username")
            or data.get("email")
            or request.args.get("identifier")
            or request.args.get("username")
        )
        options = get_passkey_authentication_options(identifier=identifier)
        return jsonify(options), 200
    except Exception as e:
        safe_print(f"WebAuthn login options error: {e}")
        return jsonify({"message": f"Failed to generate login options: {e}"}), 500


@app.route("/api/webauthn/login/verify", methods=["POST"])
@rate_limit(max_requests=15, window_seconds=60, key_prefix="webauthn_login_verify")
def webauthn_login_verify():
    """Verify passkey assertion response and issue authenticated session."""
    try:
        data = request.get_json() if request.is_json else {}
        if not data:
            return jsonify({"message": "Invalid or missing WebAuthn login payload"}), 400

        credential_payload = data.get("credential") if ("credential" in data and isinstance(data["credential"], dict)) else data
        client_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "127.0.0.1").split(",")[0].strip()

        success, msg, user = verify_passkey_authentication(
            credential_payload=credential_payload,
            client_ip=client_ip
        )

        if not success or not user:
            return jsonify({"success": False, "message": msg}), 401

        uid = user.get("uid")
        username = user.get("username")
        user_role = get_user_role(uid)

        token_res = generate_token({"username": username, "uid": uid, "role": user_role})
        raw_token = token_res[0] if isinstance(token_res, tuple) else token_res
        s_token = session_token(raw_token)
        session["token"] = s_token

        # Create session tracking and login activity records
        try:
            record_login_activity(uid, request, status="Success")
            create_user_session(uid, s_token, request)
            ensure_default_user_dashboard_data(uid, user)
        except Exception as e:
            safe_print(f"WebAuthn session tracking warning: {e}")

        response = jsonify({
            "success": True,
            "message": "Passkey authentication successful",
            "token": s_token,
            "user": {
                "uid": uid,
                "username": username,
                "email": user.get("email"),
                "role": user_role,
                "fullName": user.get("full_name") or username,
            }
        })
        response.set_cookie(
            "token",
            s_token,
            httponly=True,
            samesite="Lax",
            max_age=int(os.getenv("TOKEN_EXPIRATION", "3600") or 3600)
        )
        return response, 200

    except Exception as e:
        safe_print(f"WebAuthn login verify error: {e}")
        return jsonify({"success": False, "message": f"Authentication failed: {e}"}), 500


@app.route("/api/webauthn/credentials", methods=["GET"])
@require_auth
def webauthn_get_credentials():
    """Retrieve all registered passkeys for the authenticated user."""
    try:
        credentials = get_user_passkeys(g.user["uid"])
        return jsonify({"credentials": credentials}), 200
    except Exception as e:
        safe_print(f"WebAuthn get credentials error: {e}")
        return jsonify({"message": f"Error retrieving passkeys: {e}"}), 500


@app.route("/api/webauthn/credentials/<int:cred_id>", methods=["DELETE"])
@require_auth
def webauthn_delete_credential(cred_id):
    """Delete a registered passkey credential belonging to the authenticated user."""
    try:
        client_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "127.0.0.1").split(",")[0].strip()
        success, msg = delete_user_passkey(g.user["uid"], cred_id, client_ip)
        if not success:
            return jsonify({"success": False, "message": msg}), 400
        return jsonify({"success": True, "message": msg}), 200
    except Exception as e:
        safe_print(f"WebAuthn delete credential error: {e}")
        return jsonify({"success": False, "message": f"Error deleting passkey: {e}"}), 500


def init_app_database():
    """Ensure database tables and columns are initialized across standalone and WSGI runtimes."""
    try:
        from api.init import db_init
        from api.dashboard_db import init_dashboard_db
        from api.admin_db import init_admin_db
        from api.webauthn_db import init_webauthn_db
        db_init()
        init_dashboard_db()
        init_admin_db()
        init_webauthn_db()
    except Exception as e:
        safe_print(f"Database init warning: {e}")


# Automatically initialize schema on non-testing startup (Gunicorn / WSGI / Standalone)
if not os.getenv("TESTING") and not app.config.get("TESTING"):
    init_app_database()


if __name__ == "__main__":
    debug_mode = os.getenv("SERVER_DEBUG", "False").lower() in ("true", "1", "yes")
    host_addr = os.getenv("SERVER_HOST", "0.0.0.0") or "0.0.0.0"
    port_env = os.getenv("SERVER_PORT", "5000")
    port_num = int(port_env) if port_env and port_env.isdigit() else 5000
    app.run(debug=debug_mode, host=host_addr, port=port_num)
