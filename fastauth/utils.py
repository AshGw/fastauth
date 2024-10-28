from hashlib import sha256
from secrets import token_urlsafe
from base64 import urlsafe_b64encode
from fastauth.libtypes import GrantSecurityParams, QueryParams
from typing import Optional


def name_cookie(*, name: str) -> str:
    return "fastauth" + "." + name


def get_slashless_url(url: str) -> str:  # pragma: no cover  # TODO: test it
    """without the trailing slash"""
    return url[:-1] if url.endswith("/") else url


def gen_oauth_params() -> GrantSecurityParams:
    state: str = token_urlsafe(96)[:128]
    code_verifier = token_urlsafe(96)[:128]
    code_challenge = urlsafe_b64encode(
        sha256(code_verifier.encode("ascii")).digest()
    ).decode("ascii")[:-1]
    code_challenge_method = "S256"
    return GrantSecurityParams(
        state, code_verifier, code_challenge, code_challenge_method
    )


def gen_csrf_token() -> str:
    return token_urlsafe(96)[:128]


def querify_kwargs(kwargs: Optional[QueryParams] = None) -> str:
    if kwargs is None:
        return ""
    query_string = "&".join([f"{key}={value}" for key, value in sorted(kwargs.items())])
    return f"&{query_string}"
