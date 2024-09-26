from flask import Flask, request, jsonify
from flask_cors import CORS
import os
from dotenv import load_dotenv

load_dotenv(dotenv_path=".env")

app = Flask(__name__)






if __name__ == "__main__":
    app.run(debug=os.getenv("SERVER_DEBUG"), host=os.getenv("SERVER_HOST"), port=os.getenv("SERVER_PORT"))