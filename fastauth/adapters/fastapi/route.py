from typing import Callable, Coroutine, Any
from fastapi.routing import APIRoute
from fastauth.adapters.fastapi.request import FastAPIRequest
from fastapi import Request, Response


class FastAuthRoute(APIRoute):
    def get_route_handler(self) -> Callable[[Request], Coroutine[Any, Any, Response]]:
        original_route_handler = super().get_route_handler()

        async def fastauth_route_handler(request: Request) -> Response:
            return await original_route_handler(
                FastAPIRequest(request.scope, request.receive)
            )

        return fastauth_route_handler
