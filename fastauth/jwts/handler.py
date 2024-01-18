from typing import Optional
from fastauth.types import JWT, ViewableJWT
from logging import Logger

from jose.exceptions import JOSEError  # type: ignore

from fastauth.data import Cookies
from fastauth.utils import auth_cookie_name
from fastauth.requests import OAuthRequest
from fastauth.responses import OAuthResponse
from fastauth.jwts.operations import decipher_jwt
from fastauth.data import StatusCode


class JWTHandler:
	def __init__(
		self,
		*,
		req: OAuthRequest,
		secret: str,
		logger: Logger,
		debug: bool,
	) -> None:
		self.logger = logger
		self.req = req
		self.secret = secret
		self.debug = debug

	def get_jwt(self) -> OAuthResponse:
		encrypted_jwt: Optional[str] = self.req.cookies.get(
			auth_cookie_name(cookie_name=Cookies.JWT.name)
		)
		if encrypted_jwt:
			try:
				jwt: JWT = decipher_jwt(encrypted_jwt=encrypted_jwt, key=self.secret)
				return OAuthResponse(
					content=ViewableJWT(jwt=jwt), status_code=StatusCode.OK
				)
			except JOSEError as e:
				self._handle_error(e)

		return OAuthResponse(
			content=ViewableJWT(jwt=None), status_code=StatusCode.UNAUTHORIZED
		)

	def _handle_error(self, error: JOSEError) -> None:  # pragma: no cover
		if self.debug:
			raise error
		self.logger.warning(error)
