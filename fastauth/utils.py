from hashlib import sha256
from secrets import token_urlsafe
from base64 import urlsafe_b64encode
from fastauth._types import GrantSecurityParams, QueryParams
from fastauth.requests import OAuthRequest
from typing import Optional


def name_cookie(*, name: str) -> str:
    return "fastauth" + "." + name


def get_base_url(request: OAuthRequest) -> str:  # pragma: no cover  # TODO: test it
    """without the trailing slash"""
    url = str(request.base_url)
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


def base_redirect_url(
    *,
    response_type: str,
    authorizationUrl: str,
    client_id: str,
    redirect_uri: str,
    state: str,
    code_challenge: str,
    code_challenge_method: str,
    kwargs: QueryParams,
) -> str:
    return (
        f"{authorizationUrl}?"
        f"response_type={response_type}"
        f"&client_id={client_id}"
        f"&redirect_uri={redirect_uri}"
        f"&state={state}"
        f"&code_challenge={code_challenge}"
        f"&code_challenge_method={code_challenge_method}"
        f"{querify_kwargs(kwargs)}"
    )
