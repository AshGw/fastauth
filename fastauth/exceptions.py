from fastauth.types import ProviderResponse
from pydantic import ValidationError


class WrongKeyLength(Exception):
    def __init__(self) -> None:
        super().__init__("Key length must be exactly 32 bit")


class SchemaValidationError(Exception):
    def __init__(
        self,
        *,
        provider: str,
        resource: str,
        validation_error: ValidationError,
        debug: bool,
        provider_response_data: ProviderResponse,
    ) -> None:
        self.display = (
            f"Error during {resource} validation for {provider}. "
            f"The defined schema does not match the received JSON data. "
            f"Error details: {validation_error}\n"
        )
        if debug:
            self.display = (
                self.display + f"{provider} response: {provider_response_data}"
            )
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
            "The received code verifier does not match the expected code verifier,"
            " possible tampering"
        )
        super().__init__(self.display)


class InvalidTokenAcquisitionRequest(Exception):
    def __init__(
        self, *, provider: str, debug: bool, provider_response_data: ProviderResponse
    ) -> None:
        self.display = (
            "There's an issue with acquiring the access token from "
            f"{provider}'s authorization server. It is due to incorrect/invalid "
            "request body parameters (`code`, `code_verifier`, `state`). "
        )
        if debug:
            self.display = (
                self.display + f"{provider} response: {provider_response_data}"
            )
        super().__init__(self.display)


class InvalidUserInfoAccessRequest(Exception):
    def __init__(
        self, *, provider: str, debug: bool, provider_response_data: ProviderResponse
    ) -> None:
        self.display = (
            "The request for the resource is invalid, "
            "usually due to an invalid/expired `access_token` "
        )
        if debug:
            self.display = (
                self.display + f"{provider} response: {provider_response_data}"
            )
        super().__init__(self.display)
