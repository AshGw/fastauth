from typing import Optional, Dict
from fastauth.utils import get_slashless_url
from fastapi.requests import Request


class FastAPIRequest(Request):
    def get_cookie(self, cookie_name: str) -> Optional[str]:
        return self.cookies.get(cookie_name)

    @property
    def get_all_cookies(self) -> Dict[str, str]:
        return self.cookies

    @property
    def is_secure(self) -> bool:
        return self.url.is_secure

    @property
    def get_slashless_base_url(self) -> str:
        return get_slashless_url(str(self.base_url))
