from typing import Optional
from logging import Logger
from overrides import override
from pydantic import ValidationError

from fastauth._types import ProviderJSONResponse

from fastauth.providers.google.schemas import (
    GoogleUserInfo,
    serialize_user_info,
    serialize_access_token,
)
from fastauth.exceptions import (
    InvalidTokenAcquisitionRequest,
    InvalidUserInfoAccessRequest,
    SchemaValidationError,
)
from fastauth.providers.base import Provider
from fastauth.data import OAuthURLs, StatusCode
from fastauth.responses import OAuthRedirectResponse
from fastauth.grant_redirect import AuthGrantRedirect
from fastauth.utils import log_action

SUCCESS_STATUS_CODES = (StatusCode.OK, StatusCode.CREATED)


class Google(Provider):
    def __init__(
        self,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        debug: bool,
        logger: Logger,
    ):
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri,
            authorizationUrl=OAuthURLs.Google.authorizationUrl,
            tokenUrl=OAuthURLs.Google.tokenUrl,
            userInfo=OAuthURLs.Google.userInfo,
            provider=OAuthURLs.Google.__name__.lower(),
            debug=debug,
            logger=logger,
        )

    @log_action
    @override
    def authorize(
        self, *, state: str, code_challenge: str, code_challenge_method: str
    ) -> OAuthRedirectResponse:  # pragma: no cover
        self.logger.info(
            f"Redirecting the client to the resource owner via the {self.provider}"
            f" authorization server"
        )
        return AuthGrantRedirect(
            provider=self,
            state=state,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            scope="openid%20profile%20email",
            service="lso",
            access_type="offline",
            flowName="GeneralOAuthFlow",
        )()

    @log_action
    @override
    def get_access_token(
        self, *, code_verifier: str, code: str, state: str
    ) -> Optional[str]:
        self.logger.info(
            f"Requesting the access token from {self.provider}'s authorization server"
        )
        response = self._access_token_request(
            code_verifier=code_verifier, code=code, state=state
        )

        response_data: ProviderJSONResponse = response.json()

        if response.status_code not in SUCCESS_STATUS_CODES:
            token_acquisition_error = InvalidTokenAcquisitionRequest(
                provider=self.provider,
                debug=True,
                provider_response_data=response_data,
            )
            self.logger.warning(token_acquisition_error)
            if self.debug:
                raise token_acquisition_error
            return None
        try:
            access_token: str = serialize_access_token(response_data)
            self.logger.info(f"Access token acquired successfully from {self.provider}")
            return access_token
        except ValidationError as ve:
            schema_error = SchemaValidationError(
                provider=self.provider,
                resource="access token",
                validation_error=ve,
                debug=self.debug,
                provider_response_data=response_data,
            )
            self.logger.warning(schema_error)
            if self.debug:
                raise schema_error
            return None

    @log_action
    @override
    def get_user_info(self, access_token: str) -> Optional[GoogleUserInfo]:
        self.logger.info(
            f"Requesting user information from the {self.provider}'s resource server"
        )
        response = self._user_info_request(access_token=access_token)
        if response.status_code not in SUCCESS_STATUS_CODES:
            resource_access_error = InvalidUserInfoAccessRequest(
                provider=self.provider,
                debug=True,
                provider_response_data=response.json(),
            )
            self.logger.warning(resource_access_error)
            if self.debug:
                raise resource_access_error
            return None

        provider_response_data: ProviderJSONResponse = response.json()

        try:
            user_info: GoogleUserInfo = serialize_user_info(provider_response_data)
            self.logger.info(
                f"User information acquired successfully from " f"{self.provider}"
            )
            return user_info

        except ValidationError as ve:
            schema_validation_error = SchemaValidationError(
                provider=self.provider,
                resource="user information",
                validation_error=ve,
                debug=True,
                provider_response_data=provider_response_data,
            )
            self.logger.critical(schema_validation_error)
            if self.debug:
                raise schema_validation_error
            return None
