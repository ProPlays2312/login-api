from api.utils import not_null, is_email


def test_not_null_with_valid_value():
    assert not_null("hello") == "hello"
    assert not_null(123) == 123
    assert not_null(False) is False


def test_not_null_with_none():
    result = not_null(None)
    assert "Error: Value is null" in result


def test_is_email_valid():
    email = "test@example.com"
    assert is_email(email) == email


def test_is_email_invalid():
    result = is_email("notanemail")
    assert "Error: Malformed email" in result
