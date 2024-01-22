from __future__ import annotations
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
from datetime import datetime

_F = TypeVar("_F", bound=Callable[..., Any])


QueryParams = MutableMapping[str, str]

ProviderJSONResponse = Mapping[Any, Any]

ProviderResponse = Union[ProviderJSONResponse, str]


class ViewableJWT(TypedDict):
    jwt: Optional[JWT]


class UserInfo(TypedDict):
    user_id: str
    email: str
    name: str
    avatar: str


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
