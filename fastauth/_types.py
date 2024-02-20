from __future__ import annotations
from datetime import datetime
from fastauth.responses import OAuthResponse, OAuthRedirectResponse
from fastauth.adapters.response import FastAuthRedirectResponse, FastAuthResponse
from typing import (
    Any,
    Callable,
    TypeVar,
    NamedTuple,
    TypedDict,
    NewType,
    Optional,
    MutableMapping,
    Mapping,
    Union,
)

_F = TypeVar("_F", bound=Callable[..., Any])


AccessToken = NewType("AccessToken", str)

QueryParams = MutableMapping[str, str]

ProviderJSONResponse = Mapping[str, Any]

ProviderResponse = Union[ProviderJSONResponse, str]

OAuthBaseResponse = Union[OAuthRedirectResponse, OAuthResponse]
FastAuthBaseResponse = Union[FastAuthRedirectResponse, FastAuthResponse]


class ProviderResponseData(NamedTuple):
    status_code: int
    json: ProviderJSONResponse
    text: str


class ViewableJWT(TypedDict):
    """
    What the user will see when navigating to the
    jwt endpoint, they should get a JSON object, which is {jwt: null}
    if they're not authenticated, and a non-null value if they are.
    """

    jwt: Optional[JWT]


class UserInfo(TypedDict):
    user_id: str
    email: str
    name: str
    avatar: Optional[str]  # some do not have an avatar


class JWT(TypedDict):
    iss: str
    sub: str
    iat: datetime
    exp: datetime
    user_info: UserInfo


class GrantSecurityParams(NamedTuple):
    state: str
    code_verifier: str
    code_challenge: str
    code_challenge_method: str


class FallbackSecrets(NamedTuple):
    secret_1: str
    secret_2: str
    secret_3: str
    secret_4: str
    secret_5: str
