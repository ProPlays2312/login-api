"""Service layer for VaultAuth Admin Dashboard."""

import os
from datetime import datetime, timedelta
from api.db import execute_query
from api.utils import safe_print
from api.rbac import get_user_role, ROLES


def record_audit_log(event_type, actor_uid=None, actor_username=None, target_uid=None,
                     target_username=None, ip_address="127.0.0.1", status="Success", details=None):
    """Insert an audit log entry."""
    try:
        execute_query(
            """INSERT INTO audit_logs (event_type, actor_uid, actor_username, target_uid,
               target_username, ip_address, status, details, created_at)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW())""",
            (event_type, actor_uid, actor_username, target_uid, target_username,
             ip_address, status, details)
        )
    except Exception as e:
        safe_print(f"Audit log error: {e}")


def get_admin_dashboard_stats():
    """Aggregate all statistics for Admin Overview cards."""
    try:
        # Total users
        r = execute_query("SELECT COUNT(*) as cnt FROM users")
        total_users = r[0]["cnt"] if isinstance(r, list) and r else 0

        # Active users (is_active = TRUE)
        r = execute_query("SELECT COUNT(*) as cnt FROM users WHERE is_active = TRUE")
        active_users = r[0]["cnt"] if isinstance(r, list) and r else 0

        # Administrators
        r = execute_query("SELECT COUNT(*) as cnt FROM users WHERE role = 'admin'")
        admins = r[0]["cnt"] if isinstance(r, list) and r else 0

        # Active sessions (non-revoked, non-expired)
        now = datetime.now()
        r = execute_query(
            "SELECT COUNT(*) as cnt FROM active_sessions WHERE is_active = TRUE AND (revoked_at IS NULL) AND (expires_at IS NULL OR expires_at > %s)",
            (now,)
        )
        active_sessions = r[0]["cnt"] if isinstance(r, list) and r else 0

        # Failed login attempts (last 24h)
        since = datetime.now() - timedelta(hours=24)
        r = execute_query(
            "SELECT COUNT(*) as cnt FROM login_activity WHERE status = 'Failed' AND created_at >= %s",
            (since,)
        )
        failed_logins = r[0]["cnt"] if isinstance(r, list) and r else 0

        # Suspicious activities: audit_logs with status='Failed' or event_type like UNAUTHORIZED in last 24h
        try:
            r = execute_query(
                "SELECT COUNT(*) as cnt FROM audit_logs WHERE (status = 'Failed' OR event_type LIKE '%UNAUTHORIZED%' OR event_type LIKE '%SUSPICIOUS%') AND created_at >= %s",
                (since,)
            )
            suspicious = r[0]["cnt"] if isinstance(r, list) and r else 0
        except Exception:
            suspicious = 0

        return {
            "total_users": total_users,
            "active_users": active_users,
            "administrators": admins,
            "active_sessions": active_sessions,
            "failed_logins_24h": failed_logins,
            "suspicious_activities_24h": suspicious,
        }
    except Exception as e:
        safe_print(f"Admin stats error: {e}")
        return {
            "total_users": 0, "active_users": 0, "administrators": 0,
            "active_sessions": 0, "failed_logins_24h": 0, "suspicious_activities_24h": 0
        }


def get_all_users_admin(search=None, role_filter=None, status_filter=None, page=1, per_page=20):
    """Retrieve all users with optional filters, with role lookup."""
    try:
        conditions = []
        params = []

        if search:
            conditions.append("(LOWER(username) LIKE %s OR LOWER(email) LIKE %s OR CAST(uid AS TEXT) LIKE %s)")
            term = f"%{search.lower()}%"
            params.extend([term, term, term])

        if role_filter and role_filter != "all":
            conditions.append("role = %s")
            params.append(role_filter.lower())

        if status_filter and status_filter != "all":
            if status_filter.lower() == "active":
                conditions.append("is_active = TRUE")
            elif status_filter.lower() == "inactive":
                conditions.append("is_active = FALSE")

        where = "WHERE " + " AND ".join(conditions) if conditions else ""
        offset = (page - 1) * per_page

        count_res = execute_query(f"SELECT COUNT(*) as cnt FROM users {where}", tuple(params) if params else None)
        total = count_res[0]["cnt"] if isinstance(count_res, list) and count_res else 0

        query = f"""
        SELECT uid, username, email, full_name, phone, is_active, c_date, role
        FROM users {where}
        ORDER BY uid DESC
        LIMIT %s OFFSET %s
        """
        p = list(params) + [per_page, offset]
        rows = execute_query(query, tuple(p))

        users = []
        if isinstance(rows, list):
            for u in rows:
                role_key = (u.get("role") or "user").lower()
                users.append({
                    "uid": u["uid"],
                    "username": u["username"],
                    "email": u["email"],
                    "full_name": u.get("full_name") or u["username"],
                    "phone": u.get("phone") or "",
                    "is_active": u.get("is_active", True),
                    "role": role_key,
                    "role_title": ROLES.get(role_key, "End User"),
                    "c_date": u["c_date"].isoformat() if hasattr(u["c_date"], "isoformat") else str(u.get("c_date", "")),
                })

        return {"users": users, "total": total, "page": page, "per_page": per_page, "pages": max(1, -(-total // per_page))}
    except Exception as e:
        safe_print(f"Admin get users error: {e}")
        return {"users": [], "total": 0, "page": 1, "per_page": per_page, "pages": 1}


def admin_create_user(username, email, password, full_name=None, phone=None, role="user"):
    """Create a new user (admin action)."""
    from werkzeug.security import generate_password_hash
    from api.security import validate_email, validate_username, validate_password_strength, sanitize_string
    try:
        validate_email(email)
        validate_username(username)
        ok, _, errs = validate_password_strength(password)
        if not ok:
            return False, f"Weak password: {'; '.join(errs)}"

        if full_name:
            full_name = sanitize_string(full_name, 100)

        hashed = generate_password_hash(password)
        c_date = datetime.now().strftime("%Y-%m-%d")
        role = role.lower() if role.lower() in ("admin", "user") else "user"

        res = execute_query(
            "INSERT INTO users (username, password, email, c_date, full_name, phone, is_active, role) VALUES (%s, %s, %s, %s, %s, %s, TRUE, %s) RETURNING uid",
            (username, hashed, email, c_date, full_name, phone, role)
        )
        if isinstance(res, str) and res.startswith("Error"):
            return False, res
        new_uid = res[0]["uid"] if isinstance(res, list) and res else None
        # Seed security settings
        if new_uid:
            execute_query(
                "INSERT INTO user_security_settings (uid, mfa_enabled, recovery_email, recovery_email_verified, password_strength, password_last_changed, department, role, joined_date) VALUES (%s, TRUE, %s, FALSE, 'Strong', NOW(), 'General', %s, CURRENT_DATE) ON CONFLICT (uid) DO NOTHING",
                (new_uid, email, ROLES.get(role, "End User"))
            )
        return True, {"uid": new_uid, "username": username, "email": email}
    except ValueError as ve:
        return False, str(ve)
    except Exception as e:
        safe_print(f"Admin create user error: {e}")
        return False, str(e)


def admin_update_user(target_uid, data, actor_uid):
    """Update user fields (admin)."""
    from api.security import sanitize_string, validate_email
    allowed_fields = {}
    if "full_name" in data:
        try:
            allowed_fields["full_name"] = sanitize_string(data["full_name"], 100)
        except ValueError as ve:
            return False, str(ve)
    if "email" in data:
        try:
            allowed_fields["email"] = validate_email(data["email"])
        except ValueError as ve:
            return False, str(ve)
    if "phone" in data:
        allowed_fields["phone"] = sanitize_string(str(data["phone"])[:20], 20) if data["phone"] else None
    if "is_active" in data:
        allowed_fields["is_active"] = bool(data["is_active"])

    if not allowed_fields:
        return True, "No changes"

    sets = ", ".join(f"{k} = %s" for k in allowed_fields)
    vals = list(allowed_fields.values()) + [target_uid]
    res = execute_query(f"UPDATE users SET {sets} WHERE uid = %s", tuple(vals))
    if isinstance(res, str) and res.startswith("Error"):
        return False, res
    return True, "User updated"


def admin_toggle_user_status(target_uid, is_active, actor_uid):
    """Activate or deactivate a user account."""
    res = execute_query("UPDATE users SET is_active = %s WHERE uid = %s RETURNING uid", (is_active, target_uid))
    if isinstance(res, list) and res:
        if not is_active:
            # Revoke all sessions on deactivation
            execute_query("UPDATE active_sessions SET is_active = FALSE, revoked_at = NOW() WHERE uid = %s AND is_active = TRUE", (target_uid,))
        return True, "Account status updated"
    return False, "User not found"


def admin_delete_user(target_uid, actor_uid):
    """Permanently delete a user and all their data (cascade)."""
    # Confirm user exists first
    check = execute_query("SELECT uid, username FROM users WHERE uid = %s", (target_uid,))
    if not isinstance(check, list) or not check:
        return False, "User not found"
    username = check[0]["username"]
    res = execute_query("DELETE FROM users WHERE uid = %s RETURNING uid", (target_uid,))
    if isinstance(res, list) and res:
        return True, f"User '{username}' permanently deleted"
    return False, "Delete failed"


def get_admin_all_sessions(search=None, status_filter=None, page=1, per_page=20):
    """Get all sessions across all users for admin view."""
    try:
        conditions = []
        params = []

        if search:
            conditions.append("(LOWER(u.username) LIKE %s OR LOWER(u.email) LIKE %s OR LOWER(s.device_name) LIKE %s)")
            term = f"%{search.lower()}%"
            params.extend([term, term, term])

        if status_filter == "active":
            conditions.append("s.is_active = TRUE AND (s.revoked_at IS NULL)")
        elif status_filter == "revoked":
            conditions.append("s.is_active = FALSE")

        where = "WHERE " + " AND ".join(conditions) if conditions else ""
        offset = (page - 1) * per_page

        count_res = execute_query(
            f"SELECT COUNT(*) as cnt FROM active_sessions s JOIN users u ON s.uid = u.uid {where}",
            tuple(params) if params else None
        )
        total = count_res[0]["cnt"] if isinstance(count_res, list) and count_res else 0

        query = f"""
        SELECT s.id, s.session_id, s.uid, u.username, u.email, s.device_name,
               s.device_type, s.browser, s.os, s.ip_address, s.location,
               s.created_at, s.last_activity, s.is_active, s.expires_at, s.revoked_at
        FROM active_sessions s
        JOIN users u ON s.uid = u.uid
        {where}
        ORDER BY s.last_activity DESC
        LIMIT %s OFFSET %s
        """
        p = list(params) + [per_page, offset]
        rows = execute_query(query, tuple(p))

        sessions = []
        now = datetime.now()
        if isinstance(rows, list):
            for r in rows:
                expires_at = r.get("expires_at")
                is_expired = expires_at and expires_at < now if isinstance(expires_at, datetime) else False
                is_active = r.get("is_active", False) and not is_expired

                def fmt_dt(dt):
                    if not dt:
                        return "—"
                    if hasattr(dt, "strftime"):
                        return dt.strftime("%b %d, %Y %I:%M %p")
                    return str(dt)

                sessions.append({
                    "id": r["id"],
                    "session_id": r.get("session_id"),
                    "uid": r["uid"],
                    "username": r["username"],
                    "email": r["email"],
                    "device_name": r.get("device_name", "Unknown"),
                    "device_type": r.get("device_type", "desktop"),
                    "browser": r.get("browser", "—"),
                    "os": r.get("os", "—"),
                    "ip_address": r.get("ip_address", "—"),
                    "location": r.get("location", "—"),
                    "created_at": fmt_dt(r.get("created_at")),
                    "last_activity": fmt_dt(r.get("last_activity")),
                    "is_active": is_active,
                    "status": "Active" if is_active else ("Revoked" if r.get("revoked_at") else "Expired"),
                })

        return {"sessions": sessions, "total": total, "page": page, "per_page": per_page, "pages": max(1, -(-total // per_page))}
    except Exception as e:
        safe_print(f"Admin sessions error: {e}")
        return {"sessions": [], "total": 0, "page": 1, "per_page": per_page, "pages": 1}


def admin_revoke_session(session_id, actor_uid):
    """Revoke a session by session_id (admin)."""
    res = execute_query(
        "UPDATE active_sessions SET is_active = FALSE, revoked_at = NOW() WHERE session_id = %s AND is_active = TRUE RETURNING id",
        (session_id,)
    )
    if isinstance(res, list) and res:
        return True, "Session revoked"
    return False, "Session not found or already revoked"


def admin_revoke_all_user_sessions(target_uid, actor_uid):
    """Revoke all active sessions for a specific user (admin)."""
    res = execute_query(
        "UPDATE active_sessions SET is_active = FALSE, revoked_at = NOW() WHERE uid = %s AND is_active = TRUE RETURNING id",
        (target_uid,)
    )
    count = len(res) if isinstance(res, list) else 0
    return True, f"Revoked {count} session(s)"


def get_admin_login_activity(search=None, status_filter=None, date_from=None, date_to=None, page=1, per_page=25):
    """Get all login activity for admin monitoring."""
    try:
        conditions = []
        params = []

        if search:
            conditions.append("(LOWER(u.username) LIKE %s OR LOWER(u.email) LIKE %s)")
            term = f"%{search.lower()}%"
            params.extend([term, term])

        if status_filter and status_filter != "all":
            conditions.append("LOWER(la.status) = %s")
            params.append(status_filter.lower())

        if date_from:
            try:
                conditions.append("la.created_at >= %s")
                params.append(datetime.fromisoformat(date_from))
            except Exception:
                pass

        if date_to:
            try:
                dt_to = datetime.fromisoformat(date_to) + timedelta(days=1)
                conditions.append("la.created_at < %s")
                params.append(dt_to)
            except Exception:
                pass

        where = "WHERE " + " AND ".join(conditions) if conditions else ""
        offset = (page - 1) * per_page

        count_res = execute_query(
            f"SELECT COUNT(*) as cnt FROM login_activity la JOIN users u ON la.uid = u.uid {where}",
            tuple(params) if params else None
        )
        total = count_res[0]["cnt"] if isinstance(count_res, list) and count_res else 0

        query = f"""
        SELECT la.id, la.uid, u.username, u.email, la.device_name, la.device_type,
               la.browser, la.os, la.location, la.ip_address, la.status, la.created_at
        FROM login_activity la
        JOIN users u ON la.uid = u.uid
        {where}
        ORDER BY la.created_at DESC
        LIMIT %s OFFSET %s
        """
        p = list(params) + [per_page, offset]
        rows = execute_query(query, tuple(p))

        activities = []
        if isinstance(rows, list):
            for r in rows:
                created = r.get("created_at")
                created_str = created.strftime("%b %d, %Y %I:%M %p") if hasattr(created, "strftime") else str(created or "")
                activities.append({
                    "id": r["id"],
                    "uid": r["uid"],
                    "username": r["username"],
                    "email": r["email"],
                    "device_name": r.get("device_name", "—"),
                    "device_type": r.get("device_type", "desktop"),
                    "browser": r.get("browser", "—"),
                    "os": r.get("os", "—"),
                    "location": r.get("location", "—"),
                    "ip_address": r.get("ip_address", "—"),
                    "status": r.get("status", "Unknown"),
                    "created_at": created_str,
                    "created_at_iso": created.isoformat() if hasattr(created, "isoformat") else str(created or ""),
                })

        return {"activities": activities, "total": total, "page": page, "per_page": per_page, "pages": max(1, -(-total // per_page))}
    except Exception as e:
        safe_print(f"Admin login activity error: {e}")
        return {"activities": [], "total": 0, "page": 1, "per_page": per_page, "pages": 1}


def get_audit_logs(search=None, event_filter=None, page=1, per_page=25):
    """Retrieve audit log entries with optional filters."""
    try:
        conditions = []
        params = []

        if search:
            conditions.append("(LOWER(actor_username) LIKE %s OR LOWER(target_username) LIKE %s OR LOWER(event_type) LIKE %s)")
            term = f"%{search.lower()}%"
            params.extend([term, term, term])

        if event_filter and event_filter != "all":
            conditions.append("LOWER(event_type) LIKE %s")
            params.append(f"%{event_filter.lower()}%")

        where = "WHERE " + " AND ".join(conditions) if conditions else ""
        offset = (page - 1) * per_page

        count_res = execute_query(f"SELECT COUNT(*) as cnt FROM audit_logs {where}", tuple(params) if params else None)
        total = count_res[0]["cnt"] if isinstance(count_res, list) and count_res else 0

        query = f"""
        SELECT id, event_type, actor_uid, actor_username, target_uid, target_username,
               ip_address, status, details, created_at
        FROM audit_logs {where}
        ORDER BY created_at DESC
        LIMIT %s OFFSET %s
        """
        p = list(params) + [per_page, offset]
        rows = execute_query(query, tuple(p))

        logs = []
        if isinstance(rows, list):
            for r in rows:
                created = r.get("created_at")
                created_str = created.strftime("%b %d, %Y %I:%M %p") if hasattr(created, "strftime") else str(created or "")
                logs.append({
                    "id": r["id"],
                    "event_type": r["event_type"],
                    "actor_uid": r.get("actor_uid"),
                    "actor_username": r.get("actor_username") or "System",
                    "target_uid": r.get("target_uid"),
                    "target_username": r.get("target_username") or "—",
                    "ip_address": r.get("ip_address", "—"),
                    "status": r.get("status", "Success"),
                    "details": r.get("details") or "",
                    "created_at": created_str,
                })

        return {"logs": logs, "total": total, "page": page, "per_page": per_page, "pages": max(1, -(-total // per_page))}
    except Exception as e:
        safe_print(f"Audit logs error: {e}")
        return {"logs": [], "total": 0, "page": 1, "per_page": per_page, "pages": 1}


def get_admin_settings():
    """Retrieve all admin settings (non-secret)."""
    try:
        rows = execute_query("SELECT setting_key, setting_value FROM admin_settings ORDER BY id")
        settings = {}
        if isinstance(rows, list):
            for r in rows:
                settings[r["setting_key"]] = r["setting_value"]
        # Augment with read-only env-derived values (never expose secrets)
        settings["otp_configured"] = bool(os.getenv("PLUNK_API_KEY"))
        settings["smtp_configured"] = bool(os.getenv("PLUNK_API_KEY"))
        settings["cors_origins"] = os.getenv("CORS_ORIGINS", "http://localhost:3000,http://localhost:5500")
        return settings
    except Exception as e:
        safe_print(f"Admin settings error: {e}")
        return {}


def update_admin_settings(updates, actor_uid):
    """Update admin settings (safe keys only)."""
    ALLOWED_KEYS = {
        "session_timeout", "max_failed_attempts", "otp_expiry_seconds",
        "password_min_length", "mfa_required", "app_name"
    }
    updated = []
    for key, val in updates.items():
        if key not in ALLOWED_KEYS:
            continue
        execute_query(
            "UPDATE admin_settings SET setting_value = %s, updated_at = NOW() WHERE setting_key = %s",
            (str(val), key)
        )
        updated.append(key)
    return bool(updated), f"Updated: {', '.join(updated)}" if updated else "No valid settings updated"


def get_roles_overview():
    """Get role distribution and permission mapping."""
    try:
        rows = execute_query(
            "SELECT role, COUNT(*) as count FROM users GROUP BY role ORDER BY count DESC"
        )
        role_counts = {}
        if isinstance(rows, list):
            for r in rows:
                role_counts[r["role"] or "user"] = r["count"]

        PERMISSIONS_MAP = {
            "admin": [
                "users.view", "users.create", "users.edit", "users.delete",
                "roles.view", "roles.manage", "sessions.view", "sessions.revoke",
                "audit.view", "settings.manage"
            ],
            "user": ["users.view"]
        }

        return {
            "roles": [
                {
                    "key": "admin",
                    "title": "Enterprise Admin",
                    "description": "Full system access with all administrative privileges",
                    "count": role_counts.get("admin", 0),
                    "permissions": PERMISSIONS_MAP["admin"],
                    "color": "#7047eb"
                },
                {
                    "key": "user",
                    "title": "End User",
                    "description": "Standard user with limited read access",
                    "count": role_counts.get("user", 0),
                    "permissions": PERMISSIONS_MAP["user"],
                    "color": "#1d4ed8"
                }
            ],
            "permissions": [
                {"key": "users.view", "label": "View Users", "category": "Users"},
                {"key": "users.create", "label": "Create Users", "category": "Users"},
                {"key": "users.edit", "label": "Edit Users", "category": "Users"},
                {"key": "users.delete", "label": "Delete Users", "category": "Users"},
                {"key": "roles.view", "label": "View Roles", "category": "RBAC"},
                {"key": "roles.manage", "label": "Manage Roles", "category": "RBAC"},
                {"key": "sessions.view", "label": "View Sessions", "category": "Sessions"},
                {"key": "sessions.revoke", "label": "Revoke Sessions", "category": "Sessions"},
                {"key": "audit.view", "label": "View Audit Logs", "category": "Security"},
                {"key": "settings.manage", "label": "Manage Settings", "category": "System"},
            ]
        }
    except Exception as e:
        safe_print(f"Roles overview error: {e}")
        return {"roles": [], "permissions": []}
