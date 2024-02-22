from typing import Literal, Type
from fastauth.frameworks import Framework, FastAPI
from fastauth.adapters.fastapi.response import FastAPIBaseResponse
from fastauth.adapters.fastapi.use_response import use_fastapi_response


def use_response(
    framework: Framework,
    response_type: Literal["json", "redirect"],
) -> Type[FastAPIBaseResponse]:
    if isinstance(framework, FastAPI):
        return use_fastapi_response(response_type)
    else:
        raise NotImplementedError
