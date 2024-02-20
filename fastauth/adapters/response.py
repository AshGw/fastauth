from typing import Optional, Literal
from abc import abstractmethod
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
