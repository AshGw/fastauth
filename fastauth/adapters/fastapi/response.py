from typing import Optional, Literal, Mapping, Union
from fastapi.responses import Response
from fastauth.adapters.response import FastAuthResponse, FastAuthRedirectResponse
from overrides import override
from datetime import datetime
from urllib.parse import quote


class FastAPIResponse(Response, FastAuthResponse):
    @override
    def set_auth_cookie(
        self,
        key: str,
        value: str = "",
        max_age: Optional[int] = None,
        expires: Optional[datetime | str | int] = None,
        path: str = "/",
        domain: Optional[str] = None,
        secure: bool = False,
        httponly: bool = False,
        samesite: Literal["lax", "strict", "none"] = "lax",
    ) -> None:
        return self.set_cookie(
            key=key,
            value=value,
            max_age=max_age,
            expires=expires,
            path=path,
            domain=domain,
            secure=secure,
            httponly=httponly,
            samesite=samesite,
        )

    @override
    def delete_auth_cookie(
        self,
        key: str,
        path: str = "/",
        domain: Optional[str] = None,
        secure: bool = False,
        httponly: bool = False,
        samesite: Literal["lax", "strict", "none"] = "lax",
    ) -> None:
        return self.delete_cookie(
            key=key,
            path=path,
            domain=domain,
            secure=secure,
            httponly=httponly,
            samesite=samesite,
        )


class FastAPIRedirectResponse(FastAPIResponse, FastAuthRedirectResponse):
    def __init__(
        self,
        url: str,
        status_code: int = 307,
        headers: Optional[Mapping[str, str]] = None,
    ) -> None:
        super().__init__(content=b"", status_code=status_code, headers=headers)
        self.headers["location"] = quote(str(url), safe=":/%#?=@[]!$&'()*+,;")


FastAPIBaseResponse = Union[FastAPIResponse, FastAPIRedirectResponse]
