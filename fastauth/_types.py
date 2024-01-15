from typing import Any, Callable, TypeVar, NamedTuple

F = TypeVar('F', bound=Callable[..., Any])

class OAuthParams(NamedTuple):
    state: str
    code_verifier: str
    code_challenge: str
    code_challenge_method: str
