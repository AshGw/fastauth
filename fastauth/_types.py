from __future__ import annotations
from datetime import datetime
from fastauth.responses import OAuthResponse, OAuthRedirectResponse
from typing import (
    Any,
    Callable,
    TypeVar,
    NamedTuple,
    TypedDict,
    Optional,
    MutableMapping,
    Mapping,
    Union,
)

_F = TypeVar("_F", bound=Callable[..., Any])

QueryParams = MutableMapping[str, str]

ProviderJSONResponse = Mapping[str, Any]

ProviderResponse = Union[ProviderJSONResponse, str]

OAuthBaseResponse = Union[OAuthRedirectResponse, OAuthResponse]


class ViewableJWT(TypedDict):
    jwt: Optional[JWT]


class UserInfo(TypedDict):
    user_id: str
    email: str
    name: str
    avatar: Optional[str]  # some do not have an avatar make it optional


class JWT(TypedDict):
    iss: str
    sub: str
    iat: datetime
    exp: datetime
    user_info: UserInfo


class OAuthParams(NamedTuple):
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
