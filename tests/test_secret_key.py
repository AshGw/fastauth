from pytest import raises

from fastauth.jwts.helpers import generate_secret, validate_key
from fastauth.exceptions import WrongKeyLength


def test_generate_secret():
    secret_key = generate_secret()
    assert len(secret_key) == 32, "Key length should be 32 characters"
    assert set(
        secret_key
    ).issubset(
        set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-?$#+-*")
    ), "Generated secret key should only contain alphanumeric, _, -, ?, $, #, +, or * characters"


def test_check_key_length_valid():
    key = "a" * 32
    validate_key(key)


def test_check_key_length_invalid():
    key = "short_key"
    with raises(WrongKeyLength):
        validate_key(key)
