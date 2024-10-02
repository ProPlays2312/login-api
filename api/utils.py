# Description: This file contains the UDFs that are used in the API.

def not_null(value):
    try:
        if value is not None:
            return value
        else:
            raise Exception("Value is null")
    except Exception as e:
        print(f"Error: {e}")
        return None

def is_email(email):
    try:
        if "@" in email:
            return email
        else:
            return None
    except Exception as e:
        print(f"Error: {e}")
        return None