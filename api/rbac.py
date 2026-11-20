"""Role-Based Access Control (RBAC) decorators and helpers for VaultAuth SSO."""

from functools import wraps
from flask import g, jsonify, request
from api.db import execute_query
from api.utils import safe_print
from api.security import log_security_event

ROLES = {
    "user": "End User",
    "admin": "Enterprise Admin"
}

VALID_ROLES = set(ROLES.keys())


def get_user_role(uid):
    """Retrieve the assigned role of a user from the database."""
    try:
        rows = execute_query("SELECT role FROM users WHERE uid = %s", (uid,))
        if rows and len(rows) > 0 and isinstance(rows[0], dict):
            return (rows[0].get("role") or "user").lower().strip()
    except Exception as e:
        safe_print(f"[RBAC] get_user_role error: {e}")
    return "user"


def require_role(*allowed_roles):
    """
    Decorator to enforce role permissions on protected routes.
    Must be stacked after @require_auth.
    """
    normalized_allowed = {r.lower().strip() for r in allowed_roles}

    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            user = getattr(g, "user", None)
            if not user or not user.get("uid"):
                return jsonify({
                    "success": False,
                    "message": "Authentication required."
                }), 401

            uid = user["uid"]
            role = get_user_role(uid)
            g.role = role

            if role not in normalized_allowed:
                log_security_event(
                    "UNAUTHORIZED_ACCESS_ATTEMPT",
                    uid=uid,
                    details=f"endpoint={request.path} role={role} required={list(normalized_allowed)}"
                )
                return jsonify({
                    "success": False,
                    "message": "Access denied. Insufficient role permissions.",
                    "required_role": list(normalized_allowed)
                }), 403

            return f(*args, **kwargs)
        return decorated
    return decorator


def require_admin(f):
    """Shortcut decorator requiring Enterprise Admin role."""
    return require_role("admin")(f)


def is_admin(uid):
    """Check if a given user UID has the admin role."""
    return get_user_role(uid) == "admin"
