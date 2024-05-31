from typing import Optional, Dict
from fastauth.utils import get_slashless_url
from fastapi.requests import Request
from fastauth.adapters.request import FastAuthRequest
from overrides import override


class FastAPIRequest(Request, FastAuthRequest):
    @override
    def get_cookie(self, cookie_name: str) -> Optional[str]:
        return self.cookies.get(cookie_name)

    @override
    def all_cookies(self) -> Dict[str, str]:
        return self.cookies

    @override
    def is_connection_secure(self) -> bool:
        return self.url.is_secure

    @override
    def slashless_base_url(self) -> str:
        return get_slashless_url(str(self.base_url))

    @override
    def slashless_current_url(self) -> str:
        return get_slashless_url(str(self.url))
