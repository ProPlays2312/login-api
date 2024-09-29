from flask import Flask, request, jsonify, session, sessions
from flask_cors import CORS
import os
from dotenv import load_dotenv
from opperation import get_users, register, auth_user
from api.session import generate_token, session_token, verify_token

load_dotenv(dotenv_path=".env")

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_USE_SIGNER"] = True
app.config["SESSION_KEY_PREFIX"] = "token"
app.config["PERMANENT_SESSION_LIFETIME"] = os.getenv("TOKEN_EXPIRATION")
app.config["SESSION_COOKIE_NAME"] = "token"
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Strict"
CORS(app)

@app.route("/api/users", methods=["GET"])
def users():
    result = get_users()
    return jsonify(result)

@app.route("/api/users/<int:id>", methods=["GET"])
def users_id(id):
    user = get_users(id)
    if user is not None:
        return jsonify(user)
    else:
        return jsonify({"message": "User not found"}), 404

@app.route("/api/register", methods=["POST"])
def create_user():
    data = request.get_json()
    if data is not None:
        pass
    else:
        return jsonify({"message": "Data is null"}), 400
    try:
        result = register(data)
        return jsonify(result)
    except Exception as e:
        return jsonify({"message": f"Error: {e}"}), 500
    
@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json()
    if data is not None:
        pass
    else:
        return jsonify({"message": "Data is null"}), 400
    try:
        result = auth_user(data["login"], data["password"])
        if result is not None:
            pass
        else:
            return jsonify({"message": "User not found"}), 404
    except Exception as e:
        return jsonify({"message": f"Error: {e}"}), 500
    uid = get_users(result["user"])[0]["id"]
    user = get_users(result["user"])[0]["user"]
    token = generate_token({"user": user, "uid": uid})
    session["token"] = session_token(token)
    return jsonify({"message": "Login successful"})


if __name__ == "__main__":
    app.run(debug=os.getenv("SERVER_DEBUG"), host=os.getenv("SERVER_HOST"), port=os.getenv("SERVER_PORT"))