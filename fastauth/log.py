from logging import getLogger
from typing import TypeVar, ParamSpec, Callable
from fastauth.providers.base import Provider

logger = getLogger("fastauth")

_T = TypeVar("_T")
_PSpec = ParamSpec("_PSpec")


def log_action(f: Callable[_PSpec, _T]) -> Callable[_PSpec, _T]:
    def wrap(*args: _PSpec.args, **kwargs: _PSpec.kwargs) -> _T:
        provider = next((arg for arg in args if isinstance(arg, Provider)), None)
        if not provider:
            return f(*args, **kwargs)
        if f.__name__ == provider.authorize.__name__:
            provider.logger.info(
                f"Redirecting the client to the resource owner via"
                f" {provider.provider} authorization server"
            )
        if f.__name__ == provider.get_access_token.__name__:
            provider.logger.info(
                f"Requesting the access token from {provider.provider} "
                f"authorization server"
            )
        if f.__name__ == provider.get_user_info.__name__:
            provider.logger.info(
                f"Requesting user information from {provider.provider} "
                f"resource server"
            )
        return f(*args, **kwargs)

    return wrap
