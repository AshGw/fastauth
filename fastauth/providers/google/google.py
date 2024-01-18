from typing import Optional
from logging import Logger

from fastauth.providers.google.user_schema import (
    GoogleUserInfo,
    GoogleUserJSONData,
    serialize,
)
from fastauth.exceptions import (
    InvalidTokenAquisitionRequest,
    InvalidAccessTokenName,
    InvalidResourceAccessRequest,
)
from fastauth.providers.base import Provider
from fastauth.data import OAuthURLs, StatusCode
from fastauth.responses import OAuthRedirectResponse
from fastauth.grant_redirect import AuthGrantRedirect
from fastauth.utils import tokenUrl_payload
from httpx import post, get
from httpx import Response as HttpxResponse


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
            flowName="GeneralOAuthFlow",  # you can add more
        )()

    def get_access_token(
        self, *, code_verifier: str, code: str, state: str
    ) -> Optional[str]:
        self.logger.info("Requesting the access token from the authorization server")
        response = self._access_token_request(
            code_verifier=code_verifier, code=code, state=state
        )
        if response.status_code not in {StatusCode.OK, StatusCode.CREATED}:
            _invalid_token_request = InvalidTokenAquisitionRequest(response.json())
            self.logger.warning(_invalid_token_request)
            if self.debug:
                raise _invalid_token_request
            return None

        access_token: Optional[str] = response.json().get(self.access_token_name)
        if access_token is None:
            _invalid_token_name_err = InvalidAccessTokenName()
            self.logger.warning(_invalid_token_name_err)
            if self.debug:
                raise _invalid_token_name_err
            return None
        self.logger.info("Access token acquired successfully")
        return access_token

    def get_user_info(self, access_token: str) -> Optional[GoogleUserInfo]:
        self.logger.info("Requesting the resource from the resource server")
        response = self._user_info_request(access_token=access_token)
        if response.status_code not in {StatusCode.OK, StatusCode.CREATED}:
            err = InvalidResourceAccessRequest(response.json())
            self.logger.warning(err)
            if self.debug:
                raise err
            return None
        json_user_data: GoogleUserJSONData = response.json()
        user_info: GoogleUserInfo = serialize(json_user_data)
        return user_info

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
            data=tokenUrl_payload(
                provider=self,
                code=code,
                state=state,
                code_verifier=code_verifier,
            ),
        )
