from typing import Literal, Type
from fastauth.frameworks import Framework, FastAPI
from fastauth.adapters.fastapi.response import (
    FastAPIJSONResponse,
    FastAPIResponse,
    FastAPIRedirectResponse,
    FastAPIBaseResponse,
)


def use_response(
    framework: Framework,
    response_type: Literal["normal", "json", "redirect"] = "normal",
) -> Type[FastAPIBaseResponse]:
    if isinstance(framework, FastAPI):
        if response_type == "redirect":
            return FastAPIRedirectResponse
        elif response_type == "json":
            return FastAPIJSONResponse
        else:
            return FastAPIResponse
    else:
        raise NotImplementedError
