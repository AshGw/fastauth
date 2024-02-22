from typing import Literal, Type
from fastauth.adapters.fastapi.response import (
    FastAPIJSONResponse,
    FastAPIRedirectResponse,
    FastAPIBaseResponse,
)


def use_fastapi_response(
    response_type: Literal["json", "redirect"]
) -> Type[FastAPIBaseResponse]:
    if response_type == "redirect":
        return FastAPIRedirectResponse
    if response_type == "json":
        return FastAPIJSONResponse
