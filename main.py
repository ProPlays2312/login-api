from flask import Flask, request, jsonify, session
from flask_cors import CORS
import json
import os
from pathlib import Path
from dotenv import load_dotenv

from opperation import get_users, register, auth_user, create_otp, verify_otp
from api.token import generate_token, session_token, verify_token

load_dotenv(dotenv_path=Path(__file__).resolve().parent / ".env")
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("TOKEN_SECRET", "vault-auth-secret-key-change-in-production")

CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)


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
def create_user():
    data = request.get_json()
    if data is None:
        return jsonify({"message": "Data is null"}), 400
    try:
        result = register(data)
        return jsonify(result)
    except Exception as e:
        return jsonify({"message": f"Error: {e}"}), 500


@app.route("/api/login", methods=["POST"])
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
            return jsonify({"message": "User not found"}), 404
    except Exception as e:
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
        return jsonify({"message": "Login successful", "token": s_token})
    except Exception as e:
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
        return jsonify({"message": "User not found"}), 404
    elif err == "Account is deactivated":
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

    # If real email dispatch failed (e.g. SMTP credentials missing or bad password)
    if otp_info.get("email_sent") is False:
        err_detail = otp_info.get("email_err") or "Email could not be delivered"
        return jsonify({
            "message": f"Email delivery failed: {err_detail}. Please set valid SMTP_EMAIL and SMTP_APP_PASSWORD in .env.",
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

    return jsonify(response_data), 200


@app.route("/api/otp/verify", methods=["POST"])
@app.route("/api/login/otp/verify", methods=["POST"])
@app.route("/api/login/otp", methods=["POST"])
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
        return jsonify({"message": "User not found"}), 404
    elif err == "Account is deactivated":
        return jsonify({"message": "Account is deactivated"}), 403
    elif err or not user:
        return jsonify({"message": "Invalid or expired OTP"}), 401

    try:
        uid = user.get("uid") or 0
        username = user.get("username") or identifier
        token_res = generate_token({"username": username, "uid": uid})
        raw_token = token_res[0] if isinstance(token_res, tuple) else token_res
        s_token = session_token(raw_token)
        session["token"] = s_token

        return jsonify({
            "message": "OTP login successful",
            "token": s_token,
            "user": {
                "uid": uid,
                "username": username,
                "email": user.get("email")
            }
        }), 200
    except Exception as e:
        return jsonify({"message": f"Error: {e}"}), 500


@app.route("/api/verify", methods=["GET", "POST"])
def verify():
    auth_header = request.headers.get("Authorization")
    token = None
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ", 1)[1]
    elif request.is_json and request.get_json():
        token = request.get_json().get("token")
    elif request.args.get("token"):
        token = request.args.get("token")
    else:
        token = session.get("token") or request.cookies.get("token")

    if not token or not verify_token(token):
        return jsonify({"valid": False, "message": "Invalid or expired token"}), 401

    return jsonify({"valid": True, "message": "Token is valid", "token": token}), 200


@app.route("/api/logout", methods=["POST"])
def logout():
    session.pop("token", None)
    response = jsonify({"message": "Logout successful"})
    response.set_cookie("token", "", expires=0)
    return response, 200


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


if __name__ == "__main__":
    from api.init import db_init
    try:
        db_init()
    except Exception as e:
        print(f"Database init warning: {e}")

    debug_mode = os.getenv("SERVER_DEBUG", "False").lower() in ("true", "1", "yes")
    host_addr = os.getenv("SERVER_HOST", "0.0.0.0") or "0.0.0.0"
    port_env = os.getenv("SERVER_PORT", "5000")
    port_num = int(port_env) if port_env and port_env.isdigit() else 5000
    app.run(debug=debug_mode, host=host_addr, port=port_num)
