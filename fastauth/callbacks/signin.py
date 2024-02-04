from typing import Protocol, runtime_checkable

from fastauth._types import UserInfo


@runtime_checkable
class SignIn(Protocol):
    def __call__(self, user_info: UserInfo) -> None:
        ...
