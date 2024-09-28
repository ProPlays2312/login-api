from flask import Flask, request, jsonify
from flask_cors import CORS
import os
from dotenv import load_dotenv
from opperation import get_users, register, auth_user
import json
import jwt

load_dotenv(dotenv_path=".env")

app = Flask(__name__)

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
            token = jwt.encode({"user": result["id"]}, "secret",
                                 algorithm="HS256")
            return jsonify({"token": token})
        else:
            return jsonify({"message": "User not found"}), 404
    except Exception as e:
        return jsonify({"message": f"Error: {e}"}), 500

if __name__ == "__main__":
    app.run(debug=os.getenv("SERVER_DEBUG"), host=os.getenv("SERVER_HOST"), port=os.getenv("SERVER_PORT"))