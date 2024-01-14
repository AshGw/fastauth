from fastauth.providers.base import Provider
from hashlib import sha256
from secrets import token_urlsafe
from base64 import urlsafe_b64encode
from typing import Dict, Optional
from fastauth._types import OAuth2SecurityQueryParams

def auth_cookie_name(*, cookie_name: str) -> str:
    return "fastauth" + "." + cookie_name


def gen_oauth_params() -> OAuth2SecurityQueryParams:
    state: str = token_urlsafe(96)[:128]
    code_verifier = token_urlsafe(96)[:128]
    code_challenge = urlsafe_b64encode(
        sha256(code_verifier.encode("ascii")).digest()
    ).decode("ascii")[:-1]
    return state, code_verifier, code_challenge, "S256"


def gen_csrf_token() -> str:
    return token_urlsafe(64)[:84]


def querify_kwargs(kwargs: Optional[Dict[str, str]] = None) -> str:
    if kwargs is None:
        return ""
    query_string = "&".join([f"{key}={value}" for key, value in sorted(kwargs.items())])
    return f"&{query_string}"


# TODO: to be refactored
def tokenUrl_payload(
    *,
    provider: Provider,
    **kwargs: str,
) -> Dict[str, str]:
    extra_args = {key: value for _, (key, value) in enumerate(kwargs.items(), start=1)}
    return {
        "grant_type": provider.grant_type,
        "client_id": provider.client_id,
        "client_secret": provider.client_secret,
        "redirect_uri": provider.redirect_uri,
        **extra_args,
    }


def base_redirect_url(
    *,
    response_type: str,
    authorizationUrl: str,
    client_id: str,
    redirect_uri: str,
    state: str,
    code_challenge: str,
    code_challenge_method: str,
    kwargs: Dict[str, str],
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
