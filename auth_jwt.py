import flask
import jwt

def auth_jwt(func):
    def wrapper(*args, **kwargs):
        try:
            token = flask.request.headers["Authorization"]
            payload = jwt.decode(token, "secret", algorithms=["HS256"])
            return func(*args, **kwargs)
        except Exception as e:
            return flask.jsonify({"message": f"Error: {e}"}), 500
    return wrapper