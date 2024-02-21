import json
from typing import Optional, Literal, Mapping, Union, Any, Dict
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


class FastAPIJSONResponse(FastAPIResponse, FastAuthResponse):
    media_type = "application/json"

    def __init__(
        self,
        content: Any,
        status_code: int = 200,
        headers: Optional[Dict[str, str]] = None,
        media_type: Optional[str] = None,
    ) -> None:
        super().__init__(content, status_code, headers, media_type)

    def render(self, content: Any) -> bytes:
        return json.dumps(
            content,
            ensure_ascii=False,
            allow_nan=False,
            indent=None,
            separators=(",", ":"),
        ).encode("utf-8")


FastAPIBaseResponse = Union[
    FastAPIResponse, FastAPIRedirectResponse, FastAPIJSONResponse
]
