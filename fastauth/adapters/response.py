from typing import Optional, Literal, Mapping, Any, Dict
from datetime import datetime


class FastAuthResponse:
    def __init__(
        self,
        content: Any = None,
        status_code: int = 200,
        headers: Optional[Mapping[str, str]] = None,
    ) -> None:
        ...

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
        ...

    def delete_auth_cookie(
        self,
        key: str,
        path: str = "/",
        domain: Optional[str] = None,
        secure: bool = False,
        httponly: bool = False,
        samesite: Literal["lax", "strict", "none"] = "lax",
    ) -> None:
        ...


class FastAuthRedirectResponse(FastAuthResponse):
    def __init__(
        self,
        url: str,
        status_code: int = 307,
        headers: Optional[Mapping[str, str]] = None,
    ) -> None:
        super().__init__()


class FastAuthJSONResponse(FastAuthResponse):
    media_type = "application/json"

    def __init__(
        self,
        content: Any,
        status_code: int = 200,
        headers: Optional[Dict[str, str]] = None,
    ) -> None:
        super().__init__()
