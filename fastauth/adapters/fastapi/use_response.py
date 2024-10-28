from typing import Literal, Type, Union

from starlette.responses import RedirectResponse, JSONResponse


def use_fastapi_response(
    response_type: Literal["json", "redirect"],
) -> Type[Union[RedirectResponse, JSONResponse]]:
    if response_type == "redirect":
        return RedirectResponse
    if response_type == "json":
        return JSONResponse
