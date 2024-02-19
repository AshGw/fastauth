from os import urandom
from fastauth.exceptions import WrongKeyLength


def generate_secret() -> str:
    """
    generate a valid secret keys, or use
    `➜ openssl rand -hex 16`
    """
    return urandom(16).hex()


def validate_secret_key(key: str) -> str:
    if len(key) != 32:
        raise WrongKeyLength()
    return key
