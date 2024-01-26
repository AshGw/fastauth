from hashlib import sha256
from secrets import token_urlsafe
from base64 import urlsafe_b64encode
from fastauth._types import OAuthParams, QueryParams
from typing import TypeVar, ParamSpec, Callable, Optional
from fastauth.providers.base import Provider

_T = TypeVar("_T")
_PSpec = ParamSpec("_PSpec")


def log_action(f: Callable[_PSpec, _T]) -> Callable[_PSpec, _T]:
    def wrap(*args: _PSpec.args, **kwargs: _PSpec.kwargs) -> _T:
        provider = next((arg for arg in args if isinstance(arg, Provider)), None)
        if not provider:
            return f(*args, **kwargs)
        if f.__name__ == provider.authorize.__name__:
            provider.logger.info(
                f"Redirecting the client to the resource owner via"
                f" {provider.provider} authorization server"
            )
        if f.__name__ == provider.get_access_token.__name__:
            provider.logger.info(
                f"Requesting the access token from {provider.provider} "
                f"authorization server"
            )
        if f.__name__ == provider.get_user_info.__name__:
            provider.logger.info(
                f"Requesting user information from {provider.provider} "
                f"resource server"
            )
        return f(*args, **kwargs)

    return wrap


def name_cookie(*, name: str) -> str:
    return "fastauth" + "." + name


def gen_oauth_params() -> OAuthParams:
    state: str = token_urlsafe(96)[:128]
    code_verifier = token_urlsafe(96)[:128]
    code_challenge = urlsafe_b64encode(
        sha256(code_verifier.encode("ascii")).digest()
    ).decode("ascii")[:-1]
    code_challenge_method = "S256"
    return OAuthParams(state, code_verifier, code_challenge, code_challenge_method)


def gen_csrf_token() -> str:
    return token_urlsafe(64)[:84]


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
