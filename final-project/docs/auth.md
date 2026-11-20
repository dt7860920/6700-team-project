# Access control and TLS ("tier-2 auth")

Closes [#80](https://github.com/dt7860920/6700-team-project/issues/80) (unauthenticated API, no
per-client rate limiting) and [#81](https://github.com/dt7860920/6700-team-project/issues/81)
(the GitHub OAuth connector was dead code).

Everything here is **off by default** (`AUTH_REQUIRED=false`): a plain `uv run ono`,
`docker compose up`, CI and the test-suite behave exactly as before. Production turns it on.

| Piece | Where |
|---|---|
| OAuth flow, session, bearer gate, rate limiter | [`src/ono/auth.py`](../src/ono/auth.py) |
| Session token (HMAC, 12 h) | [`src/ono/github.py`](../src/ono/github.py) |
| Settings + fail-fast validator | [`src/ono/config.py`](../src/ono/config.py) (`auth_*`, `rate_limit_*`, `trusted_proxy`, `cookie_secure`) |
| TLS front door | [`Caddyfile`](../Caddyfile), `caddy` service in [`compose.yml`](../compose.yml) (`--profile tls`) |
| Tests | [`tests/test_auth.py`](../tests/test_auth.py), [`tests/test_config.py`](../tests/test_config.py) |

## What is gated

| Route | Why | Guard |
|---|---|---|
| `POST /scans` | spends real compute: clone, Semgrep, model calls, a sandbox | rate limit + auth |
| `POST /sources/check` | makes the server call `api.github.com` (request-forgery amplifier) | rate limit + auth |
| `GET /auth/github/callback` | makes the server call GitHub | rate limit (+ the CSRF `state` cookie; it is how you *get* a session, so no auth) |
| `GET /health`, `/info`, `/targets`, `/docs`, `/ui`, `GET /scans/{id}`, `GET /scans/{id}/findings`, `GET /findings/{id}` | read-only; scan/finding ids are unguessable random ids; the UI must load before sign-in | public |

"auth" means **either** of:

* a valid **session cookie** (`ono_session`) from "Sign in with GitHub", or
* `Authorization: Bearer <AUTH_API_TOKEN>` - a static token for CI / `curl` /
  `make smoke-live`, so automation never needs a browser.

Without one: **401** with `WWW-Authenticate: Bearer`. The rate limiter runs **before** the
credential check, so a flood of bad tokens is throttled before any comparison happens.

## The sign-in flow

```
browser                         ONO                                   GitHub
  | GET /auth/github/login?next=/ui/                                     |
  |------------------------------>| state = token_urlsafe(32)            |
  |   302 + Set-Cookie            |   cookies: ono_oauth_state, ono_oauth_next
  |     ono_oauth_state (HttpOnly, SameSite=Lax, Secure, Path=/auth/github, 10 min)
  |<------------------------------|                                      |
  | GET github.com/login/oauth/authorize?client_id&scope=read:user&redirect_uri&state
  |--------------------------------------------------------------------->|
  |                      (user approves)                                 |
  | 302 <callback>?code=...&state=...                                    |
  |<---------------------------------------------------------------------|
  | GET /auth/github/callback?code&state  (+ the state cookie)           |
  |------------------------------>| compare_digest(state, cookie) else 400
  |                               | POST github.com/login/oauth/access_token
  |                               |   (client_id, client_secret, code, redirect_uri) -->|
  |                               | GET api.github.com/user  (Bearer <token>)   ------>|
  |                               | ... token discarded; login kept                    |
  |   303 -> next                 | session = sign_session(login, AUTH_SESSION_SECRET)
  |     Set-Cookie ono_session (HttpOnly, SameSite=Lax, Secure, Path=/, 12 h)
  |<------------------------------|                                      |
```

* `GET /auth/me` -> `{"login": "octocat"}` or 401.
* `POST /auth/logout` -> 204, clears the cookie.
* The GitHub access token is used for exactly one request (`GET /user`) and never stored,
  logged or returned. Only the **login** is kept, inside our own signed session.
* Scope is `read:user` - ONO can see who you are and nothing else. No repository access.

### Security properties (and where each is enforced)

| Property | How |
|---|---|
| CSRF on the callback | random `state` in an HttpOnly cookie, `hmac.compare_digest` against the query parameter; missing/mismatch -> 400 and no call to GitHub |
| Outbound GitHub calls | fixed `https://` hosts, `follow_redirects=False`, 10 s / 5 s connect timeouts; a redirect from the token endpoint is a failure |
| Session cookie | HMAC-SHA256 over `{login, exp}` with `AUTH_SESSION_SECRET`; verified in constant time; 12 h expiry; `HttpOnly; SameSite=Lax; Secure` (`COOKIE_SECURE=false` only for plain-http dev) |
| Open redirect | `next` must be a same-origin path: one leading `/`, not `//`, no scheme, no `\`, no whitespace/control chars, <= 2048 chars; else `/ui/` |
| Bearer | `hmac.compare_digest`; the path is disabled entirely when `AUTH_API_TOKEN` is unset |
| Secrets | `SecretStr` in settings: not in `repr`, `/info`, `/openapi.json` or logs; error bodies never echo GitHub responses |
| Cross-site POSTs with the cookie | `SameSite=Lax` cookies are not sent on cross-site POSTs, and the gated routes take JSON bodies that HTML forms cannot produce |
| Legacy Gradio UI | it calls `ScanService` in-process and would bypass the HTTP gate, so `AUTH_REQUIRED=true` with `UI_BACKEND=gradio` is refused at startup |

## Rate limiting

A per-client-IP **token bucket** on the gated routes: `RATE_LIMIT_MAX` requests per
`RATE_LIMIT_WINDOW_S` seconds (default **30 per 60 s**, `RATE_LIMIT_MAX=0` disables). Over
the limit -> **429** with a `Retry-After` header. Buckets are shared across `POST /scans`
and `POST /sources/check`; the public routes are never limited.

Which address counts:

* `TRUSTED_PROXY=false` (default): the TCP peer. `X-Forwarded-For` is **ignored** - anyone
  can send that header, so honouring it would let a client pick its own bucket.
* `TRUSTED_PROXY=true`: use it **only** when the Caddy service is the sole way in (the app
  port is bound to loopback). Caddy *appends* the address it saw, so ONO takes the
  **right-most** entry and still ignores anything a client prepended.

**Limitation.** The limiter lives in the app process's memory. It is exact for the single
container this project deploys, but if you ever run several replicas each one enforces the
limit independently (an attacker gets N x the budget), and a restart resets it. A shared
store (Redis) is the upgrade path; the `RateLimiter` class is the seam.

## Turning it on

### 1. Register the GitHub OAuth App (one-time, in the browser)

1. GitHub -> your avatar -> **Settings** -> **Developer settings** (bottom of the left
   menu) -> **OAuth Apps** -> **New OAuth App**.
2. **Application name**: anything, e.g. `ONO (Jetstream)`.
3. **Homepage URL**: your deployment's origin, e.g. `https://ono.example.org`.
4. **Authorization callback URL**: that origin + `/auth/github/callback`, e.g.
   `https://ono.example.org/auth/github/callback`. It must match
   `GITHUB_OAUTH_CALLBACK_URL` **character for character**, scheme included.
5. Leave "Enable Device Flow" off. Click **Register application**.
6. Copy the **Client ID**. Click **Generate a new client secret** and copy it now; GitHub
   shows it once.

The requested scope (`read:user`) is chosen by ONO at login time, not in this form.

For a local try-out register a second app with callback
`http://localhost:8080/auth/github/callback` and run with `COOKIE_SECURE=false`.

### 2. Set the environment (`.env` on the instance)

```bash
AUTH_REQUIRED=true
AUTH_SESSION_SECRET=$(openssl rand -hex 32)      # >= 32 chars; rotating it signs everyone out
AUTH_API_TOKEN=$(openssl rand -hex 32)           # optional; for CI / curl / make smoke-live
GITHUB_OAUTH_CLIENT_ID=Iv1.xxxxxxxxxxxxxxxx
GITHUB_OAUTH_CLIENT_SECRET=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
GITHUB_OAUTH_CALLBACK_URL=https://ono.example.org/auth/github/callback
# behind the Caddy profile (below):
TRUSTED_PROXY=true
ONO_APP_BIND=127.0.0.1
ONO_DOMAIN=ono.example.org
```

Startup fails with a one-line reason if `AUTH_REQUIRED=true` and any of the session secret
or the three `GITHUB_OAUTH_*` values is missing, if the callback does not end in
`/auth/github/callback`, if the secrets are too short, or if `UI_BACKEND=gradio`.

### 3. Use it

```bash
# browser: open https://ono.example.org/auth/github/login  -> GitHub -> back at /ui/
curl -s https://ono.example.org/auth/me -b 'ono_session=...'        # {"login":"octocat"}

# automation: the static bearer
curl -s -X POST https://ono.example.org/scans \
     -H "Authorization: Bearer $AUTH_API_TOKEN" -H 'content-type: application/json' \
     -d '{"target_id":"pygoat"}'
AUTH_API_TOKEN=... make smoke-live BASE_URL=https://ono.example.org

# no credential -> 401; 31st request in a minute from one IP -> 429
```

## TLS with Caddy

The base stack still publishes the app on `:8080` over plain HTTP. The `tls` profile adds a
Caddy container that owns **80/443**, terminates TLS, sets `Strict-Transport-Security`
(plus `nosniff`, `X-Frame-Options: DENY`, a referrer policy) and proxies to `app:8080` over
the Compose network. It is opt-in, so `docker compose up` on a host with no domain is
unchanged.

```bash
cd final-project
cp .env.example.production .env           # then set EXECUTOR_TOKEN and the auth values above
echo "ONO_DOMAIN=ono.example.org" >> .env
echo "ONO_APP_BIND=127.0.0.1" >> .env     # app :8080 reachable from the host only
echo "TRUSTED_PROXY=true" >> .env
make compose-up-tls                       # == docker compose --profile tls up -d --build
curl https://ono.example.org/health
```

Security group: open **80** and **443**; close **8080** (with `ONO_APP_BIND=127.0.0.1` it
is bound to loopback anyway). Certificates and the ACME account live in the `caddy_data`
volume - keep it across redeploys or you re-issue every time and hit Let's Encrypt's rate
limits.

**Domain (recommended).** Point a DNS `A` record at the floating IP, set `ONO_DOMAIN` to
it, done: Caddy obtains and renews a public certificate and redirects `http://` to
`https://`.

**IP only (no DNS name).** No public CA issues certificates for a bare IP address, so
Let's Encrypt cannot help. Set `ONO_DOMAIN=149.165.154.219` and **uncomment `tls internal`**
in the `Caddyfile`: Caddy's built-in CA signs a certificate for the IP. Browsers show a
one-time "not private" warning (self-signed), `curl -k` works, or trust the root
certificate from the volume (`docker compose cp caddy:/data/caddy/pki/authorities/local/root.crt .`).
Cookies still get `Secure` (HTTPS is HTTPS, trusted CA or not). Register the OAuth App with
the `https://<ip>/auth/github/callback` callback.

**Why the app does not just serve TLS itself.** Certificates, renewal, HTTP->HTTPS
redirects and HSTS are a solved problem in Caddy and a maintenance burden in uvicorn; the
proxy also gives one place for future IP allowlists. Caddy runs with every capability
dropped except `NET_BIND_SERVICE`, `no-new-privileges`, and sits only on the default
network - it can never reach the Executor.

## What this PR does *not* do (follow-ups)

* **Frontend "Sign in with GitHub" (frontend/, owned by other PRs).** The React SPA has no
  sign-in affordance yet. When `GET /info` reports `"auth_required": true` it must (a) show
  a *Sign in with GitHub* button that navigates to `/auth/github/login?next=<current path>`,
  (b) treat a **401** from `POST /scans` / `POST /sources/check` as "redirect to
  `/auth/github/login`", (c) show the login from `GET /auth/me` and a *Sign out* that
  `POST`s `/auth/logout`, and (d) surface a **429** as "slow down, retry in N s"
  (`Retry-After`). The backend contract for all of that is in place and tested; until the
  SPA ships it, a gated deployment is usable via the bearer token and via visiting
  `/auth/github/login` by hand (the browser then holds the cookie the SPA's fetches send
  automatically).
* **Multi-replica rate limiting** (see the limitation above).
* **Per-user authorization** - there is identity (the login) but no allowlist of *which*
  GitHub users may scan; everyone who can sign in to GitHub can. An `AUTH_ALLOWED_LOGINS`
  list is the obvious next knob and `require_auth` is where it goes.
* **Read routes stay public.** `GET /scans/{id}` and findings are protected only by the
  unguessable id; if findings become sensitive, add `GUARDS` to those routes too (one
  line each).
