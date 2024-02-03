from typing import Protocol

from fastauth._types import UserInfo


class SignIn(Protocol):
    def __call__(self, user_info: UserInfo) -> None:
        ...
