from dataclasses import dataclass


@dataclass(frozen=True)
class CookiesData:
    class JWT:
        name: str = "jwt"
        max_age: int = 60 * 60 * 24 * 7  # 7 days # through the whole session

    class CSRFToken:
        name: str = "csrf-token"
        max_age = None  # session cookie

    class State:
        name: str = "state"
        max_age: int = 60 * 15  # 15 minutes

    class Codeverifier:
        name: str = "pkce.code_verifier"
        max_age: int = 60 * 15


@dataclass(frozen=True)
class OAuthURLs:
    class Google:
        authorizationUrl: str = "https://accounts.google.com/o/oauth2/auth"
        tokenUrl: str = "https://accounts.google.com/o/oauth2/token"
        userInfo: str = "https://www.googleapis.com/oauth2/v1/userinfo"

    class GitHub:
        authorizationUrl: str = "https://github.com/login/oauth/authorize"
        tokenUrl: str = "https://github.com/login/oauth/access_token"
        userInfo: str = "https://api.github.com/user"

    class Reddit:
        authorizationUrl = "https://www.reddit.com/api/v1/authorize"
        tokenUrl = "https://www.reddit.com/api/v1/access_token"
        userInfo = "https://oauth.reddit.com/api/v1/me"

    class Facebook:
        authorizationUrl = "https://www.facebook.com/v11.0/dialog/oauth"
        tokenUrl = "https://graph.facebook.com/oauth/access_token"
        userInfo = "https://graph.facebook.com/me"

    class Instagram:
        authorizationUrl = (
            "https://api.instagram.com/oauth/authorize?scope=user_profile"
        )
        tokenUrl = "https://api.instagram.com/oauth/access_token"
        userInfo = "https://graph.instagram.com/me?fields=id,username,account_type,name"

    class Spotify:
        authorizationUrl = "https://accounts.spotify.com/authorize"
        tokenUrl = "https://accounts.spotify.com/api/token"
        userInfo = "https://api.spotify.com/v1/me"


@dataclass(frozen=True)
class StatusCode:
    OK = 200
    CREATED = 201
    UNAUTHORIZED = 401
    BAD_REQUEST = 400
