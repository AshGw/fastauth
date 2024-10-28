from __future__ import annotations
from datetime import datetime
from typing import (
    Any,
    NamedTuple,
    TypedDict,
    NewType,
    Optional,
    MutableMapping,
    Mapping,
    Callable,
    Awaitable,
    Union,
)

AccessToken = NewType("AccessToken", str)
CSRFToken = NewType("CSRFToken", str)

QueryParams = MutableMapping[str, str]

ProviderJSONResponse = Mapping[str, Any]

ProviderResponse = Union[ProviderJSONResponse, str]

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]

Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]

ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]  # get em from starlette


class ProviderResponseData(NamedTuple):
    status_code: int
    json: ProviderJSONResponse
    text: str


class ViewableJWT(TypedDict):
    """
    What the developer will see when navigating to the
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
    # PKCE
    code_verifier: str
    code_challenge: str
    code_challenge_method: str


class FallbackSecrets(NamedTuple):
    secret_1: str
    secret_2: str
    secret_3: str
    secret_4: str
    secret_5: str
