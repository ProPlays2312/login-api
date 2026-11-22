"""Authentication middleware and device inspection utilities."""

from functools import wraps
from flask import request, jsonify, g, session
import re
from api.token import verify_token
from api.db import execute_query
from api.utils import safe_print


def parse_client_device(req):
    """Parse User-Agent and headers to determine device, browser, OS, and location."""
    user_agent = req.headers.get("User-Agent", "")
    ip = (
        req.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        or req.remote_addr
        or "127.0.0.1"
    )

    # 1. OS Detection
    os_name = "Unknown OS"
    if "Macintosh" in user_agent or "Mac OS X" in user_agent:
        os_name = "macOS"
    elif "Windows NT" in user_agent:
        os_name = "Windows"
    elif "iPhone" in user_agent or "iPad" in user_agent:
        os_name = "iOS"
    elif "Android" in user_agent:
        os_name = "Android"
    elif "Linux" in user_agent:
        os_name = "Linux"

    # 2. Browser Detection
    browser = "Web Browser"
    if "Edg/" in user_agent:
        match = re.search(r"Edg/([0-9]+)", user_agent)
        ver = match.group(1) if match else ""
        browser = f"Edge {ver}".strip()
    elif "Chrome/" in user_agent and "Chromium/" not in user_agent:
        match = re.search(r"Chrome/([0-9]+)", user_agent)
        ver = match.group(1) if match else ""
        browser = f"Chrome {ver}".strip()
    elif "Safari/" in user_agent and "Chrome" not in user_agent:
        match = re.search(r"Version/([0-9]+)", user_agent)
        ver = match.group(1) if match else ""
        browser = f"Safari {ver}".strip()
    elif "Firefox/" in user_agent:
        match = re.search(r"Firefox/([0-9]+)", user_agent)
        ver = match.group(1) if match else ""
        browser = f"Firefox {ver}".strip()

    # 3. Device Name & Type
    device_type = "desktop"
    if "iPhone" in user_agent:
        device_name = "Apple iPhone"
        device_type = "mobile"
    elif "Android" in user_agent:
        device_name = "Android Mobile"
        device_type = "mobile"
    elif os_name == "macOS":
        device_name = "MacBook Pro"
        device_type = "laptop"
    elif os_name == "Windows":
        device_name = "Windows PC"
        device_type = "desktop"
    else:
        device_name = f"{os_name} Device"
        device_type = "desktop"

    # Location (Local development default)
    location = "Bengaluru, India" if (ip.startswith("10.") or ip.startswith("127.") or ip.startswith("192.") or ip == "::1") else "Bengaluru, India"

    return {
        "device_name": device_name,
        "device_type": device_type,
        "browser": browser,
        "os": os_name,
        "ip_address": ip,
        "location": location,
    }


def get_token_from_request():
    """Extract auth token from headers, params, or cookies."""
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        return auth_header.split(" ", 1)[1].strip()

    custom_header = request.headers.get("X-Session-Token")
    if custom_header:
        return custom_header.strip()

    if request.is_json and request.get_json():
        json_token = request.get_json().get("token")
        if json_token:
            return json_token.strip()

    arg_token = request.args.get("token")
    if arg_token:
        return arg_token.strip()

    cookie_token = request.cookies.get("token") or request.cookies.get("vault_auth_token")
    if cookie_token:
        return cookie_token.strip()

    sess_token = session.get("token")
    if sess_token:
        return str(sess_token).strip()

    return None


def resolve_user_from_token(token):
    """Resolve user record from token, checking active sessions or tokens table."""
    if not token:
        return None

    if not verify_token(token):
        return None

    token_md5 = token.split(".")[0] if "." in token else token

    # Check active_sessions first (authoritative for session status and revocation)
    try:
        session_query = """
        SELECT s.id as session_id, s.uid, s.is_active as session_active, u.username, u.email, u.full_name, u.is_active
        FROM active_sessions s
        JOIN users u ON s.uid = u.uid
        WHERE s.session_token = %s
        ORDER BY s.id DESC
        LIMIT 1
        """
        rows = execute_query(session_query, (token,))
        if isinstance(rows, list) and len(rows) > 0:
            sess = rows[0]
            # If session is explicitly marked inactive/revoked, reject immediately
            if sess.get("session_active") is False:
                return None
            if sess.get("is_active") is not False:
                return sess
    except Exception as e:
        safe_print(f"Session lookup note: {e}")

    # Check tokens table
    try:
        token_query = """
        SELECT t.uid, u.username, u.email, u.full_name, u.is_active
        FROM tokens t
        JOIN users u ON t.uid = u.uid
        WHERE t.md5 = %s
        ORDER BY t.uid DESC
        LIMIT 1
        """
        rows = execute_query(token_query, (token_md5,))
        if isinstance(rows, list) and len(rows) > 0:
            user = rows[0]
            if user.get("is_active") is not False:
                return user
    except Exception as e:
        safe_print(f"Token lookup note: {e}")

    # Fallback: check if md5 matches any active user
    try:
        users = execute_query("SELECT uid, username, email, full_name, is_active FROM users WHERE is_active = TRUE")
        if isinstance(users, list):
            import os, hashlib
            secret = os.getenv("TOKEN_SECRET", "default-secret-token")
            for u in users:
                uname = u.get("username") or ""
                uid = u.get("uid") or ""
                h = hashlib.md5(f"{uname}:{uid}".encode())
                h.update(secret.encode())
                if h.hexdigest() == token_md5:
                    return u
    except Exception as e:
        safe_print(f"User hash check note: {e}")

    return None


def require_auth(f):
    """Decorator to enforce authentication on protected endpoints."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = get_token_from_request()
        if not token:
            return jsonify({
                "success": False,
                "message": "Authentication required. Please provide a Bearer token."
            }), 401

        user = resolve_user_from_token(token)
        if not user:
            return jsonify({
                "success": False,
                "message": "Invalid or expired session. Please log in again."
            }), 401

        g.user = user
        g.token = token

        # Update last activity for this session if it exists in active_sessions
        try:
            execute_query(
                "UPDATE active_sessions SET last_activity = NOW() WHERE session_token = %s",
                (token,)
            )
        except Exception:
            pass

        return f(*args, **kwargs)
    return decorated
