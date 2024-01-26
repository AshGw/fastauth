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
    Protocol,
    runtime_checkable,
    ParamSpec,
)

_F = TypeVar("_F", bound=Callable[..., Any])

_PSpec = ParamSpec("_PSpec")

QueryParams = MutableMapping[str, str]

ProviderJSONResponse = Mapping[str, Any]

ProviderResponse = Union[ProviderJSONResponse, str]

BaseOAuthResponse = Union[OAuthRedirectResponse, OAuthResponse]


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


@runtime_checkable
class Callbacks(Protocol):
    def on_signin(
        self, user_info: UserInfo, args: _PSpec.args, kwargs: _PSpec.kwargs
    ) -> None:
        ...

    def sign_out(
        self, user_info: UserInfo, args: _PSpec.args, kwargs: _PSpec.kwargs
    ) -> None:
        ...
