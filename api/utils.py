# Description: This file contains the UDFs that are used in the API.

def not_null(value):
    try:
        if value is not None:
            return value
        else:
            raise Exception("Value is null")
    except Exception as e:
        return f"Error: {e}"

def is_email(email):
    try:
        if "@" and "." in email:
            return email
        else:
            raise Exception("Malformed email")
    except Exception as e:
        return f"Error: {e}"