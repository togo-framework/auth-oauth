# auth-oauth

OAuth2 social login for togo [auth](https://github.com/togo-framework/auth):
Google, GitHub, Facebook. Depends on auth (plugin-depends-on-plugin).

```bash
togo install togo-framework/auth
togo install togo-framework/auth-oauth
```

Env: `APP_URL`, and per provider `OAUTH_GOOGLE_CLIENT_ID`/`_SECRET`,
`OAUTH_GITHUB_CLIENT_ID`/`_SECRET`, `OAUTH_FACEBOOK_CLIENT_ID`/`_SECRET`.
Flow: GET `/api/auth/oauth/{provider}` -> callback -> session.
