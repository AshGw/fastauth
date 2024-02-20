from typing import Protocol, Optional, Dict


class RequestProtocol(Protocol):
    def get_cookie(self, cookie_name: str) -> Optional[str]:
        ...

    def get_all_cookies(self) -> Dict[str, str]:
        ...

    def is_secure(self) -> bool:
        ...

    def get_slashless_base_url(
        self
    ) -> str:  # petition to add this word to the dictionary
        ...
