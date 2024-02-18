from typing import Protocol, runtime_checkable

from fastauth._types import UserInfo


@runtime_checkable
class SignInCallback(Protocol):
    async def __call__(self, user_info: UserInfo) -> None:
        ...
