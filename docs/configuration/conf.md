### Randoms
You might want to notify your users first, before the token is invalid which may cause errors, you might want to re-authenticate them when the session is about to expire


one way to do this is by grabbing the JWT and checking when the expiry date is due, this can be periodic depending on your needs.
