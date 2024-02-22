from typing import Literal, Type
from fastauth.adapters.fastapi.response import (
    FastAPIJSONResponse,
    FastAPIResponse,
    FastAPIRedirectResponse,
    FastAPIBaseResponse,
)


def use_fastapi_response(
    response_type: Literal["normal", "json", "redirect"] = "normal",
) -> Type[FastAPIBaseResponse]:
    if response_type == "redirect":
        return FastAPIRedirectResponse
    elif response_type == "json":
        return FastAPIJSONResponse
    else:
        return FastAPIResponse
