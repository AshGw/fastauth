from typing import Literal, Union, Type

from starlette.responses import RedirectResponse, JSONResponse

from fastauth.adapters.fastapi.use_response import use_fastapi_response


def use_response(
    response_type: Literal["json", "redirect"],
) -> Type[Union[RedirectResponse, JSONResponse]]:
    return use_fastapi_response(response_type)
