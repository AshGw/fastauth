from fastauth.requests import OAuthRequest
from typing import Optional, Literal

class SetCookie:
    def __init__(self,
                 request: OAuthRequest,
                key: str,
                value: str = "",
                max_age: Optional[int] = None,
                path: str = "/",
                domain: Optional[str] = None,
                secure: bool = False,
                httponly: bool = False,
                samesite: Optional[Literal["lax", "strict"]] = "lax",  # omit none`
    ) -> None:
        ...
    def set_cookie(
        self,
        key: str,
        value: str = "",
        max_age: Optional[int] = None,
        path: str = "/",
        domain: Optional[str] = None,
        secure: bool = False,
        httponly: bool = False,
        samesite: Optional[Literal["lax", "strict"]] = "lax", # omit none`
    ) -> None:
        ...

    def _is_secure(self):
        ...

    def __call__(self):
        self.set_cookie()
