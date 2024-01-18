from starlette.responses import JSONResponse, RedirectResponse


class OAuthResponse(JSONResponse):
	pass


class OAuthRedirectResponse(RedirectResponse):
	pass
