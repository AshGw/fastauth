from typing import Any, Callable, TypeVar, NamedTuple, TypedDict
from datetime import datetime

F = TypeVar('F', bound=Callable[..., Any])

class OAuthParams(NamedTuple):
    state: str
    code_verifier: str
    code_challenge: str
    code_challenge_method: str

class UserInfo(TypedDict):
    ... # TODO: implement it

class JWTPayload(TypedDict):
    iss: str
    sub: str
    iat: datetime
    exp: datetime
    user_info: UserInfo
