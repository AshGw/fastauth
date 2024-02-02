from logging import getLogger
from typing import TypeVar, ParamSpec, Callable
from fastauth.providers.base import Provider
from functools import wraps

logger = getLogger("fastauth")

_T = TypeVar("_T")
_PSpec = ParamSpec("_PSpec")


def log_action(f: Callable[_PSpec, _T]) -> Callable[_PSpec, _T]:
    @wraps(f)
    def wrap(*args: _PSpec.args, **kwargs: _PSpec.kwargs) -> _T:
        provider = next((arg for arg in args if isinstance(arg, Provider)), None)
        if not provider:
            raise RuntimeError(
                f"{f.__qualname__}: Can only log members of the {Provider} class"
            )
        if f.__name__ == provider.authorize.__name__:
            provider.logger.info(
                f"Redirecting the client to the resource owner via"
                f" {provider.provider} authorization server"
            )
            return f(*args, **kwargs)

        if f.__name__ == provider.get_access_token.__name__:
            provider.logger.info(
                f"Requesting the access token from {provider.provider} "
                f"authorization server"
            )
            return f(*args, **kwargs)

        if f.__name__ == provider.get_user_info.__name__:
            provider.logger.info(
                f"Requesting user information from {provider.provider} "
                f"resource server"
            )
            return f(*args, **kwargs)
        raise RuntimeError(
            f"{f.__qualname__}: No logging implementation was found for this method"
        )

    return wrap
