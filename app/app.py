from fastapi import FastAPI

from dotenv import load_dotenv
from os import getenv

from starlette.responses import JSONResponse

from fastauth.libtypes import UserInfo, FallbackSecrets
from fastauth.jwts.helpers import generate_secret
from fastauth.oauth2_options import OAuthOptions
from fastauth.providers.google.google import Google

from fastauth.adapters.fastapi.csrf_middleware import CSRFMitigationMiddleware

load_dotenv()


# What happens when someone logs in
async def push_to_db(user_info: UserInfo) -> None:
    with open("my_db", "w") as f:
        f.write(user_info["name"])


# One router takes care of everything
auth = OAuthOptions(
    debug=True,
    provider=Google(
        client_id=getenv("GOOGLE_CLIENT_ID"),  # type: ignore
        client_secret=getenv("GOOGLE_CLIENT_SECRET"),  # type: ignore
        redirect_uri=getenv("GOOGLE_REDIRECT_URI"),  # type: ignore
    ),
    signin_callback=push_to_db,
    fallback_secrets=FallbackSecrets(
        secret_1=getenv("SECRET"),  # type: ignore
        secret_2=generate_secret(),
        secret_3=generate_secret(),
        secret_4=generate_secret(),
        secret_5=generate_secret(),
    ),
)

app = FastAPI()
# Plug in the router
app.include_router(auth)

# Optional for OAuth flow, but highly recommended
app.add_middleware(CSRFMitigationMiddleware)


@app.get("/auth/in")
def logged() -> JSONResponse:
    return JSONResponse(content="youre in")


@app.get("/auth/out")
def out() -> JSONResponse:
    return JSONResponse(content="youre out")
