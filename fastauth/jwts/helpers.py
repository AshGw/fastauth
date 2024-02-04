from os import urandom
from fastauth.exceptions import WrongKeyLength


def generate_secret() -> str:
    """
    use this function to generate a valid secret key for the auth flow
    """
    return urandom(16).hex()


def validate_secret_key(key: str) -> str:
    if len(key) != 32:
        raise WrongKeyLength()
    return key[:32]
