from pytest import raises
from string import ascii_letters, digits
from fastauth.jwts.helpers import generate_secret, validate_key
from fastauth.exceptions import WrongKeyLength

ALLOWED_CHARS = "_-?$#+-*"


def test_generate_secret():
    secret_key = generate_secret()
    assert len(secret_key.encode("UTF-8")) == 32, "Key length should be 32 characters"
    assert set(
        secret_key
    ).issubset(
        set(ascii_letters + digits + ALLOWED_CHARS)
    ), f"Generated secret key should only contain alphanumeric, {ALLOWED_CHARS} characters"


def test_check_key_length_valid():
    key = "a" * 32
    validate_key(key)


def test_check_key_length_invalid():
    key = "short_key"
    with raises(WrongKeyLength):
        validate_key(key)
