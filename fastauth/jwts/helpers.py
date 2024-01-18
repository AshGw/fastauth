from random import choice
from string import ascii_letters
from fastauth.exceptions import WrongKeyLength


def generate_secret() -> str:
    """
    use this function to generate a valid secret key for the auth flow
    """
    characters = ascii_letters + "_-?$#+-*"
    return "".join(choice(characters) for _ in range(32))


def check_key_length(key: str) -> None:
    if len(key) != 32:
        raise WrongKeyLength("Key length must be exactly 32 bit")
