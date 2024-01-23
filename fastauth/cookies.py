from fastauth.responses import OAuthRedirectResponse
from fastauth.requests import OAuthRequest
from typing import Optional, Literal


class Cookie:
    http_only = True
    samesite: Literal["lax", "strict", "none"] = "lax"
    domain = None
    path = "/"

    def __init__(
        self,
        request: OAuthRequest,
        response: OAuthRedirectResponse,
    ) -> None:
        self.request = request
        self.response = response

    def set_cookie(
        self,
        key: str,
        value: str = "",
        max_age: Optional[int] = None,
    ) -> None:
        self.response.set_cookie(
            key=key,
            value=value,
            max_age=max_age,
            path=self.path,
            domain=self.domain,
            secure=self._is_secure(),
            httponly=self.http_only,
            samesite=self.samesite,
        )

    def delete(
        self,
        key: str,
    ) -> None:
        return self.response.delete_cookie(
            key=key,
            path=self.path,
            domain=self.domain,
            secure=self._is_secure(),
            httponly=self.http_only,
            samesite=self.samesite,
        )

    def get(self, key: str) -> Optional[str]:
        return self.request.cookies.get(key)

    def _is_secure(self) -> bool:
        return self.request.url.is_secure
