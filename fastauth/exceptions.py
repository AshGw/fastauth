from fastauth._types import ProviderResponse
from pydantic import ValidationError
from jose.exceptions import JOSEError


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
            f"Error details: {validation_error}"
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


class CodeVerifierNotFound(Exception):
    def __init__(self) -> None:
        self.display = "The code verifier could not be retrieved from the cookie, the user might have deleted the cookie"
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


class JSONWebTokenTampering(Exception):
    def __init__(
        self,
        *,
        error: JOSEError,
    ) -> None:
        self.display = (
            f"Error during JWT deciphering, possible tampering or use of an invalid key. "
            f"Error details: {error}"
        )
        super().__init__(self.display)
