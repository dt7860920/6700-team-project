"""Tier-2 auth: the GitHub OAuth flow (against a FAKE GitHub), the session / bearer gate on
the sensitive routes, the open-redirect guard, and per-IP rate limiting.

No test here talks to github.com: ``GitHubOAuth.transport`` is an ``httpx.MockTransport``.
"""

from __future__ import annotations

import time
from http.cookies import SimpleCookie
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from ono.api import create_app
from ono.auth import (
    DEFAULT_NEXT,
    GITHUB_TOKEN_URL,
    GITHUB_USER_URL,
    NEXT_COOKIE,
    SESSION_COOKIE,
    STATE_COOKIE,
    GitHubOAuth,
    OAuthExchangeError,
    RateLimiter,
    safe_next,
)
from ono.config import Settings
from ono.github import sign_session, verify_session

SESSION_SECRET = "unit-test-session-secret-0123456789abcdef"
API_TOKEN = "unit-test-bearer-token-0123456789"
CALLBACK = "http://testserver/auth/github/callback"
GITHUB_TOKEN = "gho_FAKE_access_token_that_must_never_leak"
SCAN = {"target_id": "pygoat"}


def auth_settings(**overrides: Any) -> Settings:
    base: dict[str, Any] = {
        "_env_file": None,
        "auth_required": True,
        "auth_session_secret": SecretStr(SESSION_SECRET),
        "auth_api_token": SecretStr(API_TOKEN),
        "github_oauth_client_id": "Iv1.unit-test-client",
        "github_oauth_client_secret": SecretStr("oauth-app-secret-never-logged"),
        "github_oauth_callback_url": CALLBACK,
        "cookie_secure": False,  # TestClient speaks plain http
        "ui_backend": "none",
    }
    base.update(overrides)
    return Settings(**base)


class FakeGitHub:
    """Stands in for github.com (token exchange) and api.github.com (user lookup)."""

    def __init__(
        self,
        *,
        login: str = "octocat",
        exchange_status: int = 200,
        exchange_body: dict[str, Any] | None = None,
        user_status: int = 200,
    ) -> None:
        self.login = login
        self.exchange_status = exchange_status
        self.exchange_body = exchange_body
        self.user_status = user_status
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if str(request.url) == GITHUB_TOKEN_URL and request.method == "POST":
            body = (
                self.exchange_body
                if self.exchange_body is not None
                else {"access_token": GITHUB_TOKEN, "token_type": "bearer", "scope": "read:user"}
            )
            return httpx.Response(self.exchange_status, json=body)
        if str(request.url) == GITHUB_USER_URL and request.method == "GET":
            if request.headers.get("Authorization") != f"Bearer {GITHUB_TOKEN}":
                return httpx.Response(401, json={"message": "Bad credentials"})
            return httpx.Response(self.user_status, json={"login": self.login, "id": 583231})
        return httpx.Response(404, json={"message": "unexpected request in test"})


def make_client(settings: Settings, github: FakeGitHub | None = None) -> TestClient:
    app = create_app(settings, mount_ui=False)
    if github is not None:
        oauth: GitHubOAuth = app.state.oauth
        oauth.transport = httpx.MockTransport(github)
    return TestClient(app)


def set_cookies(response: httpx.Response) -> dict[str, str]:
    """``{cookie name: raw Set-Cookie line}`` for every cookie a response sets."""
    return {line.split("=", 1)[0].strip(): line for line in response.headers.get_list("set-cookie")}


def cookie_value(set_cookie_line: str) -> str:
    """The (unquoted) value of a raw Set-Cookie line, as a browser would store it."""
    jar = SimpleCookie()
    jar.load(set_cookie_line)
    (morsel,) = jar.values()
    return morsel.value


def start_login(client: TestClient, next_path: str | None = None) -> tuple[str, httpx.Response]:
    params = {"next": next_path} if next_path is not None else {}
    r = client.get("/auth/github/login", params=params, follow_redirects=False)
    assert r.status_code == 302, r.text
    state = parse_qs(urlsplit(r.headers["location"]).query)["state"][0]
    return state, r


# ---------------------------------------------------------------------------
# Login redirect + state cookie
# ---------------------------------------------------------------------------


def test_login_redirects_to_github_with_state_cookie() -> None:
    with make_client(auth_settings(), FakeGitHub()) as c:
        state, r = start_login(c, "/ui/scans/abc")

    location = urlsplit(r.headers["location"])
    assert (location.scheme, location.netloc, location.path) == (
        "https",
        "github.com",
        "/login/oauth/authorize",
    )
    query = parse_qs(location.query)
    assert query["client_id"] == ["Iv1.unit-test-client"]
    assert query["scope"] == ["read:user"]
    assert query["redirect_uri"] == [CALLBACK]
    assert len(state) >= 32
    assert "client_secret" not in location.query

    cookies = set_cookies(r)
    assert f"{STATE_COOKIE}={state}" in cookies[STATE_COOKIE]
    for flag in ("HttpOnly", "SameSite=lax", "Path=/auth/github", "Max-Age=600"):
        assert flag in cookies[STATE_COOKIE], cookies[STATE_COOKIE]
    assert cookie_value(cookies[NEXT_COOKIE]) == "/ui/scans/abc"
    assert r.headers["cache-control"] == "no-store"


def test_cookies_are_secure_by_default() -> None:
    with make_client(auth_settings(cookie_secure=True), FakeGitHub()) as c:
        _, r = start_login(c)
    assert "Secure" in set_cookies(r)[STATE_COOKIE]


def test_login_is_503_when_oauth_not_configured() -> None:
    with make_client(Settings(_env_file=None)) as c:
        r = c.get("/auth/github/login", follow_redirects=False)
    assert r.status_code == 503
    assert "not configured" in r.json()["detail"]


# ---------------------------------------------------------------------------
# Callback
# ---------------------------------------------------------------------------


def test_callback_happy_path_issues_our_session_and_discards_github_token() -> None:
    github = FakeGitHub(login="octocat")
    with make_client(auth_settings(), github) as c:
        state, _ = start_login(c, "/ui/scans/abc")
        r = c.get(
            "/auth/github/callback", params={"code": "c0de", "state": state}, follow_redirects=False
        )
        assert r.status_code == 303, r.text
        assert r.headers["location"] == "/ui/scans/abc"

        cookies = set_cookies(r)
        session_line = cookies[SESSION_COOKIE]
        for flag in ("HttpOnly", "SameSite=lax", "Path=/", f"Max-Age={12 * 3600}"):
            assert flag in session_line, session_line
        # the OAuth flow cookies are gone once the session exists
        assert "Max-Age=0" in cookies[STATE_COOKIE] and "Max-Age=0" in cookies[NEXT_COOKIE]

        # The session carries the login (verifiable with OUR secret), never GitHub's token.
        session_value = session_line.split(";", 1)[0].split("=", 1)[1]
        assert verify_session(session_value, SESSION_SECRET) == "octocat"
        assert GITHUB_TOKEN not in session_value
        assert GITHUB_TOKEN not in str(r.headers)

        assert c.get("/auth/me").json() == {"login": "octocat"}
        assert c.post("/scans", json=SCAN).status_code == 202  # the gate opens

    # What we sent GitHub: a server-side exchange with the secret, then one user lookup.
    exchange, user = github.requests
    assert exchange.method == "POST" and str(exchange.url) == GITHUB_TOKEN_URL
    assert exchange.headers["Accept"] == "application/json"
    form = parse_qs(exchange.content.decode())
    assert form == {
        "client_id": ["Iv1.unit-test-client"],
        "client_secret": ["oauth-app-secret-never-logged"],
        "code": ["c0de"],
        "redirect_uri": [CALLBACK],
    }
    assert user.method == "GET" and str(user.url) == GITHUB_USER_URL
    assert user.headers["Authorization"] == f"Bearer {GITHUB_TOKEN}"


@pytest.mark.parametrize("supplied", ["", "wrong-state", None])
def test_callback_rejects_bad_or_missing_state(supplied: str | None) -> None:
    github = FakeGitHub()
    with make_client(auth_settings(), github) as c:
        start_login(c)
        params = {"code": "c0de"}
        if supplied is not None:
            params["state"] = supplied
        r = c.get("/auth/github/callback", params=params, follow_redirects=False)
        assert r.status_code == 400
        assert "state" in r.json()["detail"]
        assert SESSION_COOKIE not in set_cookies(r)
        assert c.get("/auth/me").status_code == 401
    assert github.requests == []  # no exchange attempted


def test_callback_without_state_cookie_is_rejected() -> None:
    """A forged callback (no login on this browser) never reaches GitHub."""
    github = FakeGitHub()
    with make_client(auth_settings(), github) as c:
        r = c.get(
            "/auth/github/callback",
            params={"code": "c0de", "state": "attacker-chosen"},
            follow_redirects=False,
        )
    assert r.status_code == 400
    assert github.requests == []


def test_callback_without_code_is_400() -> None:
    github = FakeGitHub()
    with make_client(auth_settings(), github) as c:
        state, _ = start_login(c)
        r = c.get(
            "/auth/github/callback",
            params={"state": state, "error": "access_denied"},
            follow_redirects=False,
        )
    assert r.status_code == 400
    assert "authorization code" in r.json()["detail"]
    assert github.requests == []


@pytest.mark.parametrize(
    "github",
    [
        FakeGitHub(exchange_status=503),
        FakeGitHub(exchange_body={"error": "bad_verification_code"}),
        FakeGitHub(user_status=500),
        FakeGitHub(login="not a valid login!"),
    ],
    ids=["exchange-5xx", "exchange-error-body", "user-5xx", "bad-login"],
)
def test_callback_failed_exchange_is_a_clean_502(github: FakeGitHub) -> None:
    with make_client(auth_settings(), github) as c:
        state, _ = start_login(c)
        r = c.get(
            "/auth/github/callback", params={"code": "c0de", "state": state}, follow_redirects=False
        )
        assert r.status_code == 502, r.text
        assert SESSION_COOKIE not in set_cookies(r)
        assert GITHUB_TOKEN not in r.text
        assert "oauth-app-secret" not in r.text
        assert c.get("/auth/me").status_code == 401


def test_exchange_never_follows_redirects() -> None:
    """A redirect from the token endpoint is a failure, not a hop to somewhere else."""
    seen: list[httpx.Request] = []

    def redirecting(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(302, headers={"location": "https://evil.example/steal"})

    oauth = GitHubOAuth("id", "secret", CALLBACK, transport=httpx.MockTransport(redirecting))
    with pytest.raises(OAuthExchangeError):
        oauth.login_for_code("c0de")
    assert len(seen) == 1


# ---------------------------------------------------------------------------
# Open-redirect guard
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("candidate", "expected"),
    [
        ("/ui/", "/ui/"),
        ("/ui/scans/abc?tab=findings", "/ui/scans/abc?tab=findings"),
        (None, DEFAULT_NEXT),
        ("", DEFAULT_NEXT),
        ("//evil.example", DEFAULT_NEXT),
        ("///evil.example", DEFAULT_NEXT),
        ("/\\evil.example", DEFAULT_NEXT),
        ("https://evil.example/ui/", DEFAULT_NEXT),
        ("javascript:alert(1)", DEFAULT_NEXT),
        ("ui/", DEFAULT_NEXT),
        ("/ui/\r\nSet-Cookie: x=y", DEFAULT_NEXT),
        (" /ui/", DEFAULT_NEXT),
        ("/" + "a" * 3000, DEFAULT_NEXT),
    ],
)
def test_safe_next(candidate: str | None, expected: str) -> None:
    assert safe_next(candidate) == expected


def test_open_redirect_via_next_is_neutralized_end_to_end() -> None:
    with make_client(auth_settings(), FakeGitHub()) as c:
        state, login = start_login(c, "//evil.example/phish")
        assert cookie_value(set_cookies(login)[NEXT_COOKIE]) == DEFAULT_NEXT
        r = c.get(
            "/auth/github/callback", params={"code": "c0de", "state": state}, follow_redirects=False
        )
    assert r.status_code == 303
    assert r.headers["location"] == DEFAULT_NEXT


# ---------------------------------------------------------------------------
# The gate on POST /scans and POST /sources/check
# ---------------------------------------------------------------------------


def test_gated_routes_need_a_credential_when_auth_required() -> None:
    with make_client(auth_settings(), FakeGitHub()) as c:
        for path, body in (("/scans", SCAN), ("/sources/check", {"repo_url": "https://x"})):
            r = c.post(path, json=body)
            assert r.status_code == 401, (path, r.text)
            assert r.headers["www-authenticate"] == "Bearer"
            assert "/auth/github/login" in r.json()["detail"]
        # The public surface is untouched.
        assert c.get("/health").status_code == 200
        assert c.get("/targets").status_code == 200
        assert c.get("/info").json()["auth_required"] is True
        assert c.get("/scans/scn_nope").status_code == 404
        assert c.get("/docs").status_code == 200


def test_valid_session_cookie_is_admitted() -> None:
    with make_client(auth_settings(), FakeGitHub()) as c:
        c.cookies.set(SESSION_COOKIE, sign_session("octocat", SESSION_SECRET))
        assert c.post("/scans", json=SCAN).status_code == 202
        assert c.get("/auth/me").json() == {"login": "octocat"}


@pytest.mark.parametrize(
    "cookie",
    [
        sign_session("octocat", SESSION_SECRET, now=int(time.time()) - 13 * 3600),  # expired
        sign_session("octocat", "some-other-secret-of-the-same-length-"),  # wrong key
        sign_session("octocat", SESSION_SECRET)[:-3] + "AAA",  # tampered signature
        "garbage",
    ],
    ids=["expired", "wrong-secret", "tampered", "garbage"],
)
def test_invalid_session_cookie_is_rejected(cookie: str) -> None:
    with make_client(auth_settings(), FakeGitHub()) as c:
        c.cookies.set(SESSION_COOKIE, cookie)
        assert c.post("/scans", json=SCAN).status_code == 401
        assert c.get("/auth/me").status_code == 401


def test_static_bearer_is_admitted_and_wrong_bearer_is_not() -> None:
    with make_client(auth_settings(), FakeGitHub()) as c:
        ok = c.post("/scans", json=SCAN, headers={"Authorization": f"Bearer {API_TOKEN}"})
        assert ok.status_code == 202, ok.text
        for header in (
            f"Bearer {API_TOKEN[:-1]}x",
            f"Bearer {API_TOKEN}extra",
            "Bearer ",
            f"Basic {API_TOKEN}",
            f"Token {API_TOKEN}",
        ):
            r = c.post("/scans", json=SCAN, headers={"Authorization": header})
            assert r.status_code == 401, header


def test_bearer_path_is_off_when_no_api_token_is_configured() -> None:
    with make_client(auth_settings(auth_api_token=None), FakeGitHub()) as c:
        r = c.post("/scans", json=SCAN, headers={"Authorization": f"Bearer {API_TOKEN}"})
        assert r.status_code == 401


def test_logout_clears_the_session() -> None:
    with make_client(auth_settings(), FakeGitHub()) as c:
        # Sign in through the real flow so the cookie jar holds the session exactly as a
        # browser would (host-only, path /), and the server's deletion matches it.
        state, _ = start_login(c)
        c.get("/auth/github/callback", params={"code": "c0de", "state": state})
        assert c.get("/auth/me").json() == {"login": "octocat"}
        r = c.post("/auth/logout")
        assert r.status_code == 204
        assert "Max-Age=0" in set_cookies(r)[SESSION_COOKIE]
        assert SESSION_COOKIE not in c.cookies
        assert c.get("/auth/me").status_code == 401


def test_auth_off_by_default_keeps_the_open_behaviour() -> None:
    """The back-compat contract: with AUTH_REQUIRED unset nothing needs a credential."""
    with make_client(Settings(_env_file=None)) as c:
        assert c.get("/info").json()["auth_required"] is False
        assert c.post("/scans", json=SCAN).status_code == 202
        assert c.get("/auth/me").status_code == 401  # no session, but nothing is gated
        assert c.post("/auth/logout").status_code == 204


def test_secrets_never_surface_in_info_or_openapi() -> None:
    with make_client(auth_settings(), FakeGitHub()) as c:
        text = c.get("/info").text + c.get("/openapi.json").text
    for secret in (SESSION_SECRET, API_TOKEN, "oauth-app-secret-never-logged"):
        assert secret not in text


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------


def test_rate_limit_exceeded_is_429_with_retry_after() -> None:
    settings = Settings(_env_file=None, rate_limit_max=3, rate_limit_window_s=60.0)
    with make_client(settings) as c:
        for _ in range(3):
            assert c.post("/scans", json={"target_id": "nope"}).status_code == 403
        r = c.post("/scans", json={"target_id": "nope"})
        assert r.status_code == 429
        assert int(r.headers["retry-after"]) >= 1
        assert "rate limit" in r.json()["detail"]
        # one bucket per client across the gated routes; the public routes are unaffected
        assert c.post("/sources/check", json={"repo_url": "https://x"}).status_code == 429
        assert c.get("/health").status_code == 200
        assert c.get("/targets").status_code == 200


def test_rate_limit_runs_before_the_auth_check() -> None:
    """A credential-stuffing flood is throttled before any secret comparison."""
    with make_client(auth_settings(rate_limit_max=2), FakeGitHub()) as c:
        assert c.post("/scans", json=SCAN).status_code == 401
        assert c.post("/scans", json=SCAN).status_code == 401
        assert c.post("/scans", json=SCAN).status_code == 429


def test_callback_shares_the_rate_limit_budget() -> None:
    """Looping login -> callback cannot be used to hammer GitHub's token endpoint."""
    github = FakeGitHub(exchange_status=503)
    with make_client(auth_settings(rate_limit_max=1), github) as c:
        state, _ = start_login(c)
        params = {"code": "c0de", "state": state}
        assert (
            c.get("/auth/github/callback", params=params, follow_redirects=False).status_code == 502
        )
        state, _ = start_login(c)  # login itself is cheap and not limited
        params = {"code": "c0de", "state": state}
        assert (
            c.get("/auth/github/callback", params=params, follow_redirects=False).status_code == 429
        )
    assert len(github.requests) == 1


def test_rate_limit_can_be_disabled() -> None:
    with make_client(Settings(_env_file=None, rate_limit_max=0)) as c:
        for _ in range(40):
            assert c.post("/scans", json={"target_id": "nope"}).status_code == 403


def test_x_forwarded_for_is_ignored_unless_trusted_proxy() -> None:
    settings = Settings(_env_file=None, rate_limit_max=2, trusted_proxy=False)
    with make_client(settings) as c:
        for ip in ("1.1.1.1", "2.2.2.2"):
            r = c.post("/scans", json={"target_id": "nope"}, headers={"X-Forwarded-For": ip})
            assert r.status_code == 403
        r = c.post("/scans", json={"target_id": "nope"}, headers={"X-Forwarded-For": "3.3.3.3"})
        assert r.status_code == 429  # spoofed header did not buy a fresh bucket


def test_trusted_proxy_keys_on_rightmost_forwarded_entry() -> None:
    settings = Settings(_env_file=None, rate_limit_max=2, trusted_proxy=True)
    with make_client(settings) as c:
        body = {"target_id": "nope"}
        assert (
            c.post("/scans", json=body, headers={"X-Forwarded-For": "1.1.1.1"}).status_code == 403
        )
        # a client prepending junk is still the same rightmost address
        spoof = {"X-Forwarded-For": "9.9.9.9, 1.1.1.1"}
        assert c.post("/scans", json=body, headers=spoof).status_code == 403
        assert (
            c.post("/scans", json=body, headers={"X-Forwarded-For": "1.1.1.1"}).status_code == 429
        )
        # a different real client has its own bucket
        assert (
            c.post("/scans", json=body, headers={"X-Forwarded-For": "2.2.2.2"}).status_code == 403
        )


def test_rate_limiter_refills_over_time_and_bounds_memory() -> None:
    now = [1000.0]
    limiter = RateLimiter(2, 10.0, clock=lambda: now[0], max_tracked=3)
    assert limiter.check("a") == 0.0
    assert limiter.check("a") == 0.0
    wait = limiter.check("a")
    assert 0.0 < wait <= 5.0  # one token refills every 5 s
    now[0] += wait
    assert limiter.check("a") == 0.0
    # Memory: only max_tracked live buckets are kept once the window has passed.
    now[0] += 100.0
    for key in ("b", "c", "d", "e"):
        limiter.check(key)
    assert len(limiter._buckets) <= 3
    with pytest.raises(ValueError, match="window_s"):
        RateLimiter(1, 0.0)


# ---------------------------------------------------------------------------
# ono.github (issue #81: it had no tests)
# ---------------------------------------------------------------------------


def test_sign_and_verify_session_roundtrip() -> None:
    token = sign_session("octocat", SESSION_SECRET, now=1_700_000_000)
    assert verify_session(token, SESSION_SECRET, now=1_700_000_000 + 11 * 3600) == "octocat"
    assert verify_session(token, SESSION_SECRET, now=1_700_000_000 + 12 * 3600) is None
    assert verify_session(token, "x" * 32, now=1_700_000_000) is None
    assert verify_session(None, SESSION_SECRET) is None
    assert verify_session("", SESSION_SECRET) is None
    assert verify_session("no-dot-here", SESSION_SECRET) is None
    assert verify_session(token + "x", SESSION_SECRET) is None
    assert verify_session(sign_session("", SESSION_SECRET), SESSION_SECRET) is None
