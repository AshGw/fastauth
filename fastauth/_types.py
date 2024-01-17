from typing import Any, Callable, TypeVar, NamedTuple, TypedDict, Optional, Dict
from datetime import datetime

F = TypeVar('F', bound=Callable[..., Any])


class QueryParams(Dict[str, str]):
    ...

class OAuthParams(NamedTuple):
    state: str
    code_verifier: str
    code_challenge: str
    code_challenge_method: str

class UserInfo(TypedDict):
    user_id: str
    email: str
    name: str
    avatar: str
    extras: Optional[Dict[str,Any]] # depending on the provider

class JWTPayload(TypedDict):
    iss: str
    sub: str
    iat: datetime
    exp: datetime
    user_info: UserInfo
