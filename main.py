from flask import Flask, request, jsonify, session, sessions
from flask_cors import CORS, cross_origin
import os
from dotenv import load_dotenv

from opperation import get_users, register, auth_user
from api.token import generate_token, session_token
from api.headers import set_headers
# from api.config import Config

load_dotenv(dotenv_path=".env")

app = Flask(__name__)

CORS(app, resources={r"/api/*": {"origins": "*"}})

cross_origin(f"{os.getenv("SERVER_HOST")}:{str(os.getenv("SERVER_PORT"))}", supports_credentials=True)

@app.route("/api/users", methods=["GET"])
def users():
    try:
        users = get_users(None)
        if users is not None:
            return jsonify(users)
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
            return jsonify({"message": "User not found"}), 404
    except Exception as e:
        return jsonify({"message": f"Error: {e}"}), 500

@app.route("/api/users/<string:id>", methods=["GET"])
def username(id):
    try:
        user = get_users(id)
        if user is not None:
            return jsonify(user)
        else:
            return jsonify({"message": "User not found"}), 404
    except Exception as e:
        return jsonify({"message": f"Error: {e}"}), 500

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
    try:
        uid = get_users(result["user"])[0]["id"]
        user = get_users(result["user"])[0]["user"]
        token = generate_token({"user": user, "uid": uid})
        session["token"] = session_token(token)
        return jsonify({"message": "Login successful"})
    except Exception as e:
        return jsonify({"message": f"Error: {e}"}), 500

if __name__ == "__main__":
    app.run(debug=os.getenv("SERVER_DEBUG"), host=os.getenv("SERVER_HOST"), port=os.getenv("SERVER_PORT"))