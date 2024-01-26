from fastauth.requests import OAuthRequest
from fastauth._types import BaseOAuthResponse
from typing import Optional, Literal


class Cookie:
    _http_only = True
    _samesite: Literal["lax", "strict", "none"] = "lax"
    _domain = None
    _path = "/"

    def __init__(
        self,
        request: OAuthRequest,
        response: BaseOAuthResponse,
    ) -> None:
        self.request = request
        self.response = response

    def set(
        self,
        *,
        key: str,
        value: str,
        max_age: Optional[int],
    ) -> None:
        self.response.set_cookie(
            key=key,
            value=value,
            max_age=max_age,
            path=self._path,
            domain=self._domain,
            secure=self._is_secure(),
            httponly=self._http_only,
            samesite=self._samesite,
        )

    def delete(
        self,
        key: str,
    ) -> None:
        return self.response.delete_cookie(
            key=key,
            path=self._path,
            domain=self._domain,
            secure=self._is_secure(),
            httponly=self._http_only,
            samesite=self._samesite,
        )

    def get(self, key: str) -> Optional[str]:
        return self.request.cookies.get(key)

    def _is_secure(self) -> bool:
        return self.request.url.is_secure
