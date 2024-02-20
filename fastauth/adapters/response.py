from abc import abstractmethod
from typing import Optional, Literal, Mapping
from datetime import datetime


class FastAuthResponse:
    @abstractmethod
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

    @abstractmethod
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


class FastAuthRedirectResponse:
    def __init__(
        self,
        url: str,
        status_code: int = 307,
        headers: Optional[Mapping[str, str]] = None,
    ) -> None:
        ...
