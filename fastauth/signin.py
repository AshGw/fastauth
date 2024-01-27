from typing import Protocol, Any

from fastauth._types import UserInfo


class SignIn(Protocol):
    def __call__(self, user_info: UserInfo, *args: Any, **kwargs: Any) -> None:
        ...
