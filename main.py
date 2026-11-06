import logging
import os
from functools import wraps

from dotenv import load_dotenv
from flask import Flask, jsonify, request, session
from flask_cors import CORS

from api.token import generate_token, session_token, verify_token
from opperation import auth_user, get_users, register

load_dotenv(dotenv_path=".env")

app = Flask(__name__)
secret_key = os.getenv("SECRET_KEY")
if not secret_key:
    raise RuntimeError("SECRET_KEY must be configured")
app.config["SECRET_KEY"] = secret_key

CORS(
    app,
    resources={
        r"/api/*": {
            "origins": os.getenv("CORS_ORIGIN", "http://localhost:3000"),
            "supports_credentials": True,
        }
    },
)
logger = logging.getLogger(__name__)


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        token = session.get("token")
        user = {
            "username": session.get("username"),
            "uid": session.get("uid"),
        }
        if not token or not user["username"] or user["uid"] is None:
            return jsonify({"message": "Authentication required"}), 401
        if not verify_token(token, user):
            session.clear()
            return jsonify({"message": "Authentication required"}), 401
        return view(*args, **kwargs)

    return wrapped


@app.route("/api/users", methods=["GET"])
@login_required
def users():
    try:
        users = get_users(None)
        if users is not None:
            return jsonify(users)
        return jsonify({"message": "Error getting users"}), 500
    except Exception:
        logger.exception("Failed to retrieve users")
        return jsonify({"message": "Internal server error"}), 500


@app.route("/api/users/<int:uid>", methods=["GET"])
def users_id(uid):
    try:
        user = get_users(uid)
        if user is not None:
            return jsonify(user)
        return jsonify({"message": "Error: User not found"}), 404
    except Exception:
        logger.exception("Failed to retrieve user by ID")
        return jsonify({"message": "Internal server error"}), 500


@app.route("/api/users/<string:user_id>", methods=["GET"])
def username(user_id):
    try:
        user = get_users(user_id)
        if user is not None:
            return jsonify(user)
        return jsonify({"message": "Error: User not found"}), 404
    except Exception:
        logger.exception("Failed to retrieve user by username")
        return jsonify({"message": "Internal server error"}), 500


@app.route("/api/register", methods=["POST"])
def create_user():
    data = request.get_json()
    if data is None:
        return jsonify({"message": "Data is null"}), 400
    try:
        return jsonify(register(data))
    except ValueError:
        return jsonify({"message": "username, password, and email are required"}), 400
    except Exception:
        logger.exception("Failed to register user")
        return jsonify({"message": "Internal server error"}), 500


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json()
    if data is None:
        return jsonify({"message": "Data is null"}), 400
    try:
        result = auth_user(data["login"], data["password"])
    except KeyError:
        return jsonify({"message": "login and password are required"}), 400
    except Exception:
        logger.exception("Failed to authenticate user")
        return jsonify({"message": "Internal server error"}), 500

    if result is None:
        return jsonify({"message": "Invalid credentials"}), 401

    try:
        token, _ = generate_token(
            {"username": result["username"], "uid": result["uid"]}
        )
        session["token"] = session_token(token)
        session["username"] = result["username"]
        session["uid"] = result["uid"]
        return jsonify({"message": "Login successful"})
    except Exception:
        logger.exception("Failed to create login session")
        return jsonify({"message": "Internal server error"}), 500


if __name__ == "__main__":
    app.run(
        debug=os.getenv("SERVER_DEBUG") == "true",
        host=os.getenv("SERVER_HOST"),
        port=os.getenv("SERVER_PORT"),
    )
