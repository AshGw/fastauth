from typing import Optional, Dict
from abc import abstractmethod


class RequestProtocol:
    @abstractmethod
    def get_cookie(self, cookie_name: str) -> Optional[str]:
        ...

    @abstractmethod
    def all_cookies(self) -> Dict[str, str]:
        ...

    @abstractmethod
    def is_connection_secure(self) -> bool:
        ...

    @abstractmethod
    def slashless_base_url(self) -> str:  # petition to add this word to the dictionary
        ...
