# Description: This file contains the headers for the API.

from flask import make_response, request

def set_headers():
    headers = {
        "X-FORWARDED-FOR": request.remote_addr,
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
        "Content-Type": "application/json",
        "X-Content-Type-Options": "nosniff",
        "X-XSS-Protection": "1; mode=block",
        "X-Frame-Options": "DENY",
        "Server": "Nginx"
    }
    return make_response("", 200, headers)
