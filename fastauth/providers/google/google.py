from typing import Optional
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
from fastauth.providers.base import Provider, log_action
from fastauth.data import OAuthURLs, StatusCode
from fastauth.responses import OAuthRedirectResponse
from fastauth.grant_redirect import AuthGrantRedirect


SUCCESS_STATUS_CODES = (StatusCode.OK, StatusCode.CREATED)


class Google(Provider):
    def __init__(
        self,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
    ):
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri,
            authorizationUrl=OAuthURLs.Google.authorizationUrl,
            tokenUrl=OAuthURLs.Google.tokenUrl,
            userInfo=OAuthURLs.Google.userInfo,
            provider=OAuthURLs.Google.__name__.lower(),
        )

    @log_action
    @override
    def authorize(
        self, *, state: str, code_challenge: str, code_challenge_method: str
    ) -> OAuthRedirectResponse:  # pragma: no cover
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
    async def get_access_token(
        self, *, code_verifier: str, code: str, state: str
    ) -> Optional[str]:
        response = await self._request_access_token(
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
    async def get_user_info(self, access_token: str) -> Optional[GoogleUserInfo]:
        response = await self._request_user_info(access_token=access_token)
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
