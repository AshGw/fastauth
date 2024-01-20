from typing import Any
from pydantic import ValidationError


class WrongKeyLength(Exception):
    pass


class SchemaValidationError(Exception):
    def __init__(self, *, provider: str, validation_error: ValidationError) -> None:
        self.display = (f"Error during schema validation for {provider}. "
                        f"The defined schema does not match the received JSON data."
                        f"Perhaps you updated the scopes without adjusting the schema. To add "
                        f"more scopes, you need to re-configure the schema accordingly. "
                        f"Error details: {validation_error}")
        super().__init__(self.display)

class InvalidState(Exception):
    def __init__(self) -> None:
        self.display = (
            "The received state does not match the expected state, possible tampering"
        )
        super().__init__(self.display)


class InvalidCodeVerifier(Exception):
    def __init__(self) -> None:
        self.display = (
            "The received code verifier does not match the expected code verifier"
        )
        super().__init__(self.display)


class InvalidTokenAcquisitionRequest(Exception):
    def __init__(self, *, provider: str, provider_error: Any) -> None:
        self.display = (
            "There's an issue with acquiring the access token from "
            f"{provider}'s authorization server. It is due to incorrect/invalid "
            "request body parameters (`code`, `code_verifier`, `state`). "
            f"{provider}'s error response: "
            f"{provider_error}"
        )
        super().__init__(self.display)


class InvalidResourceAccessRequest(Exception):
    def __init__(self, *, provider: str, provider_error: Any) -> None:
        self.display = (
            "The request for the resource is invalid, "
            "it's either due to an invalid/expired `access_token` "
            "or the wrong `Content-Type` header. "
            f"{provider}'s error response: "
            f"{provider_error}"
        )
        super().__init__(self.display)


class InvalidAccessTokenName(Exception):
    def __init__(self) -> None:
        self.display = (
            "You might want to check in with your provider over how the "
            "`access_token` is named, e.g.: `accessToken` or `token` and so on."
        )
        super().__init__(self.display)
