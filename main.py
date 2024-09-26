from flask import Flask, request, jsonify
from flask_cors import CORS
import os
from dotenv import load_dotenv
from opperation import login, register

load_dotenv(dotenv_path=".env")

app = Flask(__name__)

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data["username"]
    password = data["password"]
    try:
        if login(username, password):
            return jsonify({"message": "Login successful"})
        else:
            return jsonify({"message": "Invalid credentials"})
    except Exception as e:
        return jsonify({"message": f"Error: {e}"})





if __name__ == "__main__":
    app.run(debug=os.getenv("SERVER_DEBUG"), host=os.getenv("SERVER_HOST"), port=os.getenv("SERVER_PORT"))