from typing import Protocol, Optional, Dict


class RequestProtocol(Protocol):
    def get_cookie(self, cookie_name: str) -> Optional[str]:
        ...

    def all_cookies(self) -> Dict[str, str]:
        ...

    def is_secure(self) -> bool:
        ...

    def slashless_base_url(self) -> str:  # petition to add this word to the dictionary
        ...


class FastAuthRequest:
    def __init__(self, adaptee: RequestProtocol):
        self.adaptee = adaptee

    def get_cookie(self, cookie_name: str) -> Optional[str]:
        return self.adaptee.get_cookie(cookie_name)

    @property
    def all_cookies(self) -> Dict[str, str]:
        return self.adaptee.all_cookies()

    @property
    def is_secure(self) -> bool:
        return self.adaptee.is_secure()

    @property
    def slashless_base_url(  # petition to add this word to the dictionary
        self
    ) -> str:
        return self.adaptee.slashless_base_url()
