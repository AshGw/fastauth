from fastauth.adapters.request import FastAuthRequest
from fastauth.adapters.response import FastAuthResponse
from typing import Optional, Literal, Dict, final, Final
from fastauth.utils import name_cookie


@final
class Cookies:
    _http_only: Final[bool] = True
    _samesite: Final[Literal["lax", "strict", "none"]] = "lax"
    _domain: Final = None
    _path: Final[str] = "/"

    def __init__(
        self,
        request: FastAuthRequest,
        response: FastAuthResponse,
    ) -> None:
        self.request = request
        self.response = response

    @property
    def all(self) -> Dict[str, str]:
        return self.request.all_cookies()

    def set(
        self,
        *,
        key: str,
        value: str,
        max_age: Optional[int],
    ) -> None:
        self.response.set_auth_cookie(
            key=name_cookie(name=key),
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
        return self.response.delete_auth_cookie(
            key=name_cookie(name=key),
            path=self._path,
            domain=self._domain,
            secure=self._is_secure(),
            httponly=self._http_only,
            samesite=self._samesite,
        )

    def get(self, key: str) -> Optional[str]:
        return self.request.get_cookie(cookie_name=name_cookie(name=key))

    def _is_secure(self) -> bool:
        return self.request.is_connection_secure()
