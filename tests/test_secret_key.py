import pytest
from string import ascii_letters, digits
from fastauth.jwts.helpers import generate_secret, validate_secret_key
from fastauth.exceptions import WrongKeyLength


def test_generate_secret() -> None:
    allowed_chars = "_-?$#+-*"
    secret_key = generate_secret()
    assert len(secret_key.encode("UTF-8")) == 32, "Key length should be 32 characters"
    assert set(
        secret_key
    ).issubset(
        set(ascii_letters + digits + allowed_chars)
    ), f"Generated secret key should only contain alphanumeric, {allowed_chars} characters"


def test_check_key_length_valid():
    key = "a" * 32
    validate_secret_key(key)


def test_check_key_length_invalid():
    key = "a" * 32
    key1 = validate_secret_key(key)
    key2 = validate_secret_key(key1)[:-1]
    with pytest.raises(WrongKeyLength):
        validate_secret_key(key2)
