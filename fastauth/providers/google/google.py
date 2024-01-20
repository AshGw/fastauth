from typing import Optional
from logging import Logger

from fastauth.providers.google.schemas import (
    GoogleUserInfo,
    serialize_user_info
)
from pydantic.error_wrappers import ValidationError
from fastauth.exceptions import (
    InvalidTokenAcquisitionRequest,
    InvalidAccessTokenName,
    InvalidUserInfoAccessRequest,
    UserInfoSchemaValidationError
)
from fastauth.providers.base import Provider
from fastauth.data import OAuthURLs, StatusCode
from fastauth.responses import OAuthRedirectResponse
from fastauth.grant_redirect import AuthGrantRedirect
from fastauth.utils import token_request_payload
from httpx import post, get
from httpx import Response as HttpxResponse

SUCCESS_STATUS_CODES = (StatusCode.OK, StatusCode.CREATED)


class Google(Provider):
    access_token_name = "access_token"

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

    def redirect(
        self, *, state: str, code_challenge: str, code_challenge_method: str
    ) -> OAuthRedirectResponse:  # pragma: no cover
        self.logger.info(
            "Redirecting the client to the resource owner via the authorization server"
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

    def get_access_token(
        self, *, code_verifier: str, code: str, state: str
    ) -> Optional[str]:
        self.logger.info("Requesting the access token from the authorization server")
        response = self._access_token_request(
            code_verifier=code_verifier, code=code, state=state
        )
        if response.status_code not in SUCCESS_STATUS_CODES:
            token_acquisition_error = InvalidTokenAcquisitionRequest(
                provider=self.provider, provider_error=response.json()
            )
            self.logger.warning(token_acquisition_error)
            if self.debug:
                raise token_acquisition_error
            return None


        access_token: Optional[str] = response.json().get(self.access_token_name)
        if access_token is None:
            invalid_name_error = InvalidAccessTokenName()
            self.logger.warning(invalid_name_error)
            if self.debug:
                raise invalid_name_error
            return None
        self.logger.info("Access token acquired successfully")
        return access_token

    def get_user_info(self, access_token: str) -> Optional[GoogleUserInfo]:
        self.logger.info("Requesting the user information from the resource server")
        response = self._user_info_request(access_token=access_token)
        if response.status_code not in SUCCESS_STATUS_CODES:
            resource_access_error = InvalidUserInfoAccessRequest(
                provider=self.provider, provider_error=response.json()
            )
            self.logger.warning(resource_access_error)
            if self.debug:
                raise resource_access_error
            return None
        try:
            user_info: GoogleUserInfo = serialize_user_info(response.json())
            self.logger.info("User information acquired successfully")
            return user_info
        except ValidationError as ve:
            schema_validation_error = UserInfoSchemaValidationError(provider=self.provider, validation_error=ve)
            self.logger.critical(schema_validation_error)
            if self.debug:
                raise schema_validation_error
            return None

    def _user_info_request(self, *, access_token: str) -> HttpxResponse:
        return get(
            url=self.userInfo,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {access_token}",
            },
        )

    def _access_token_request(
        self, *, code_verifier: str, code: str, state: str
    ) -> HttpxResponse:
        return post(
            url=self.tokenUrl,
            data=token_request_payload(
                provider=self,
                code=code,
                state=state,
                code_verifier=code_verifier,
            ),
        )
