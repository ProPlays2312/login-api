from flask import Flask, request, jsonify
from flask_cors import CORS
import os
from dotenv import load_dotenv
from opperation import get_users
import json

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

@app.route("/api/users/register", methods=["POST"])
def create_user():
    data = request.get_json()
    if data is not None:
        pass
    else:
        return jsonify({"message": "Data is null"}), 400
    # todo: create user usinf function
    





if __name__ == "__main__":
    app.run(debug=os.getenv("SERVER_DEBUG"), host=os.getenv("SERVER_HOST"), port=os.getenv("SERVER_PORT"))