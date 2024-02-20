import inspect
from typing import Protocol, runtime_checkable

from fastauth._types import UserInfo


@runtime_checkable
class SignInCallback(Protocol):
    async def __call__(self, user_info: UserInfo) -> None:
        ...


def check_signin_signature(obj: SignInCallback):
    sig = inspect.signature(obj)
    if not (
        "user_info" in sig.parameters
        and sig.parameters["user_info"].annotation == UserInfo
    ):
        raise TypeError(
            f"Given object does not adhere to SignInCallback protocol: {obj}"
        )


async def push_to_db(user_info: UserInfo) -> None:
    print(f"defo pushing {user_info} to db")
