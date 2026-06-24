<!-- togo-brand -->
<p align="center">
  <img src=".github/assets/togo-mark.svg" width="96" alt="togo" />
</p>
<h1 align="center">auth-oauth</h1>
<p align="center"><sub>part of the <a href="https://github.com/togo-framework">togo-framework</a> — the full-stack Go + React framework</sub></p>

OAuth2 social login for togo [auth](https://github.com/togo-framework/auth):
Google, GitHub, Facebook. Depends on auth (plugin-depends-on-plugin).

```bash
togo install togo-framework/auth
togo install togo-framework/auth-oauth
```

Env: `APP_URL`, and per provider `OAUTH_GOOGLE_CLIENT_ID`/`_SECRET`,
`OAUTH_GITHUB_CLIENT_ID`/`_SECRET`, `OAUTH_FACEBOOK_CLIENT_ID`/`_SECRET`.
Flow: GET `/api/auth/oauth/{provider}` -> callback -> session.


---

## 💎 Premium sponsors

togo is proudly sponsored by **ID8 Media** and **One Studio**.

<p align="center">
  <a href="https://id8media.com"><img src=".github/assets/id8media.svg" height="44" alt="ID8 Media" /></a>
  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
  <a href="https://one-studio.co"><img src=".github/assets/one-studio.jpeg" height="44" alt="One Studio" /></a>
</p>
