"""Tier-2 authentication: GitHub OAuth identity, our own session, a bearer for automation,
and per-IP rate limiting. Closes issues #80 (no auth) and #81 (dead OAuth connector).

The GitHub side is *identity only* (scope ``read:user``): we never store, log or reuse the
GitHub access token. The callback exchanges the one-time ``code`` for a token, reads the
``login`` with it, discards it, and issues OUR session (``ono.github.sign_session``: HMAC
signed, 12 h expiry) as an ``HttpOnly; SameSite=Lax; Secure`` cookie.

    GET  /auth/github/login?next=/ui/   302 -> github.com/login/oauth/authorize (+ state cookie)
    GET  /auth/github/callback          verify state, exchange code, set session, 303 -> next
    GET  /auth/me                       {"login": ...} or 401
    POST /auth/logout                   clear the session cookie -> 204

Guards exported for the sensitive routes (``api.py`` adds them as route dependencies):

    rate_limited   per-client-IP token bucket -> 429 + Retry-After
    require_auth   session cookie OR ``Authorization: Bearer <auth_api_token>`` -> 401 otherwise
                   (a no-op while ``Settings.auth_required`` is False, the default)

Security notes
--------------
* OAuth ``state`` is ``secrets.token_urlsafe(32)`` in an HttpOnly cookie scoped to
  ``/auth/github`` and compared with ``hmac.compare_digest``; missing or mismatched -> 400.
* Outbound calls to GitHub: fixed HTTPS hosts, ``follow_redirects=False``, timeouts. Tests
  inject an ``httpx.MockTransport``; nothing here ever talks to the real GitHub under pytest.
* ``next`` is accepted only as a same-origin path (one leading ``/``, no ``//``, no scheme,
  no backslashes or control characters); anything else falls back to ``/ui/``.
* Bearer and session comparisons are constant-time. Secrets arrive as ``SecretStr`` and are
  read exactly where they are used.
* The rate limiter is in-process memory: correct for the single-container deployment, but
  NOT shared across replicas. ``X-Forwarded-For`` is honoured only when
  ``Settings.trusted_proxy`` is set (Caddy in front), and only its right-most entry - the
  one our proxy appended - so a client cannot pick its own bucket.
"""

from __future__ import annotations

import hmac
import logging
import math
import re
import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Annotated, Literal
from urllib.parse import urlencode, urlsplit

import httpx
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Request, Response, status
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel
from starlette.concurrency import run_in_threadpool

from ono.config import Settings
from ono.github import sign_session, verify_session
from ono.models import ErrorResponse

log = logging.getLogger(__name__)

GITHUB_AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_USER_URL = "https://api.github.com/user"
OAUTH_SCOPE = "read:user"

SESSION_COOKIE = "ono_session"
STATE_COOKIE = "ono_oauth_state"
NEXT_COOKIE = "ono_oauth_next"
AUTH_COOKIE_PATH = "/auth/github"
SESSION_MAX_AGE_S = 12 * 60 * 60  # mirrors the ``exp`` that sign_session() writes
STATE_MAX_AGE_S = 10 * 60
DEFAULT_NEXT = "/ui/"

_GITHUB_LOGIN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")
_NO_STORE = {"Cache-Control": "no-store"}


# ---------------------------------------------------------------------------
# Redirect-target validation
# ---------------------------------------------------------------------------


def safe_next(candidate: str | None) -> str:
    """Return ``candidate`` if it is a path on this origin, else :data:`DEFAULT_NEXT`.

    Accepts ``/ui/``, ``/ui/scans/abc?x=1``. Rejects ``//evil.com``, ``/\\evil.com`` (browsers
    treat ``\\`` as ``/``), ``https://...``, ``javascript:...``, anything with whitespace or
    control characters, overlong values, and relative paths without a leading slash.
    """
    if not candidate or len(candidate) > 2048:
        return DEFAULT_NEXT
    if candidate != candidate.strip() or any(c.isspace() or ord(c) < 0x20 for c in candidate):
        return DEFAULT_NEXT
    if not candidate.startswith("/") or candidate.startswith("//") or "\\" in candidate:
        return DEFAULT_NEXT
    try:
        parts = urlsplit(candidate)
    except ValueError:
        return DEFAULT_NEXT
    if parts.scheme or parts.netloc:
        return DEFAULT_NEXT
    return candidate


# ---------------------------------------------------------------------------
# GitHub OAuth (identity only)
# ---------------------------------------------------------------------------


class OAuthExchangeError(RuntimeError):
    """The code -> token exchange or the user lookup failed. Safe to show; details are logged."""


@dataclass
class GitHubOAuth:
    """The GitHub OAuth App this deployment is registered as.

    ``transport`` exists for tests (``httpx.MockTransport``); production leaves it ``None``
    and talks to the two fixed HTTPS endpoints above with redirects disabled.
    """

    client_id: str
    client_secret: str
    callback_url: str
    transport: httpx.BaseTransport | None = None

    def authorize_url(self, state: str) -> str:
        query = urlencode(
            {
                "client_id": self.client_id,
                "redirect_uri": self.callback_url,
                "scope": OAUTH_SCOPE,
                "state": state,
                "allow_signup": "false",
            }
        )
        return f"{GITHUB_AUTHORIZE_URL}?{query}"

    def login_for_code(self, code: str) -> str:
        """Exchange ``code`` for an access token, read the user's ``login``, drop the token.

        The token lives in one local variable for two HTTP calls and is never returned,
        stored or logged. Raises :class:`OAuthExchangeError` on any failure.
        """
        try:
            with httpx.Client(
                timeout=httpx.Timeout(10.0, connect=5.0),
                follow_redirects=False,
                headers={"Accept": "application/json", "User-Agent": "ONO-auth"},
                transport=self.transport,
            ) as client:
                exchange = client.post(
                    GITHUB_TOKEN_URL,
                    data={
                        "client_id": self.client_id,
                        "client_secret": self.client_secret,
                        "code": code,
                        "redirect_uri": self.callback_url,
                    },
                )
                if exchange.status_code != 200:
                    log.warning(
                        "github oauth: token exchange answered HTTP %s", exchange.status_code
                    )
                    raise OAuthExchangeError("GitHub token exchange failed")
                payload = exchange.json()
                if not isinstance(payload, dict):
                    raise OAuthExchangeError("GitHub token exchange returned an unexpected body")
                access_token = payload.get("access_token")
                if not isinstance(access_token, str) or not access_token:
                    # GitHub answers 200 with {"error": "bad_verification_code", ...} on a
                    # used/expired code. The error *code* is a fixed enum and safe to log.
                    log.warning("github oauth: no access token (error=%r)", payload.get("error"))
                    raise OAuthExchangeError("GitHub did not issue an access token")

                user = client.get(
                    GITHUB_USER_URL,
                    headers={
                        "Authorization": f"Bearer {access_token}",
                        "Accept": "application/vnd.github+json",
                        "X-GitHub-Api-Version": "2022-11-28",
                    },
                )
                del access_token
                if user.status_code != 200:
                    log.warning("github oauth: user lookup answered HTTP %s", user.status_code)
                    raise OAuthExchangeError("GitHub user lookup failed")
                profile = user.json()
        except OAuthExchangeError:
            raise
        except (httpx.HTTPError, ValueError) as exc:
            # Never include the exception text: httpx errors can quote request bodies.
            log.warning("github oauth: exchange failed (%s)", type(exc).__name__)
            raise OAuthExchangeError("Could not reach GitHub to complete sign-in") from None

        login = profile.get("login") if isinstance(profile, dict) else None
        if not isinstance(login, str) or not _GITHUB_LOGIN.fullmatch(login):
            raise OAuthExchangeError("GitHub returned an invalid login")
        return login


def build_oauth(settings: Settings) -> GitHubOAuth | None:
    """The OAuth client, or ``None`` when the three ``GITHUB_OAUTH_*`` settings are not all set."""
    if not (
        settings.github_oauth_client_id
        and settings.github_oauth_client_secret
        and settings.github_oauth_client_secret.get_secret_value()
        and settings.github_oauth_callback_url
    ):
        return None
    return GitHubOAuth(
        client_id=settings.github_oauth_client_id,
        client_secret=settings.github_oauth_client_secret.get_secret_value(),
        callback_url=settings.github_oauth_callback_url,
    )


# ---------------------------------------------------------------------------
# Per-IP rate limiting (token bucket, in-process)
# ---------------------------------------------------------------------------


class RateLimiter:
    """``max_requests`` per ``window_s`` per key, as a token bucket. ``max_requests=0`` disables.

    Single-process only: the buckets live in this interpreter's memory, so several
    replicas each enforce the limit independently (document it; a shared store would be
    the next step). Memory is bounded: once more than ``max_tracked`` keys are known,
    fully-refilled buckets are dropped (they are indistinguishable from unknown keys).
    """

    def __init__(
        self,
        max_requests: int,
        window_s: float,
        *,
        clock: Callable[[], float] = time.monotonic,
        max_tracked: int = 10_000,
    ) -> None:
        if max_requests < 0 or window_s <= 0:
            msg = "rate limiter needs max_requests >= 0 and window_s > 0"
            raise ValueError(msg)
        self.max_requests = max_requests
        self.window_s = window_s
        self._clock = clock
        self._max_tracked = max_tracked
        self._buckets: dict[str, tuple[float, float]] = {}  # key -> (tokens, last update)
        self._lock = threading.Lock()

    @property
    def enabled(self) -> bool:
        return self.max_requests > 0

    def check(self, key: str) -> float:
        """Spend one token for ``key``. Returns 0.0 when allowed, else seconds to wait."""
        if not self.enabled:
            return 0.0
        rate = self.max_requests / self.window_s
        now = self._clock()
        with self._lock:
            tokens, updated = self._buckets.get(key, (float(self.max_requests), now))
            tokens = min(float(self.max_requests), tokens + max(0.0, now - updated) * rate)
            if tokens >= 1.0:
                self._buckets[key] = (tokens - 1.0, now)
                wait = 0.0
            else:
                self._buckets[key] = (tokens, now)
                wait = (1.0 - tokens) / rate
            if len(self._buckets) > self._max_tracked:
                self._prune(now)
            return wait

    def _prune(self, now: float) -> None:
        stale = [k for k, (_, updated) in self._buckets.items() if now - updated >= self.window_s]
        for k in stale:
            del self._buckets[k]
        if len(self._buckets) > self._max_tracked:
            # Still too many live keys (an IP-spraying flood): drop the oldest ones.
            oldest = sorted(self._buckets.items(), key=lambda kv: kv[1][1])
            for k, _ in oldest[: len(self._buckets) - self._max_tracked]:
                del self._buckets[k]


def client_ip(request: Request, *, trusted_proxy: bool) -> str:
    """The address rate limits are keyed on.

    Without a trusted proxy this is the TCP peer; ``X-Forwarded-For`` is ignored because
    anyone can send it. Behind our Caddy (``trusted_proxy=True``) the proxy *appends* the
    peer it saw to the header, so only the right-most entry is trusted.
    """
    if trusted_proxy:
        forwarded = request.headers.get("x-forwarded-for", "")
        last = forwarded.rsplit(",", 1)[-1].strip()
        if last:
            return last
    return request.client.host if request.client else "unknown"


# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Principal:
    """Who is making the request. ``login`` is set only for cookie sessions."""

    kind: Literal["anonymous", "session", "bearer"]
    login: str | None = None

    @property
    def label(self) -> str:
        return f"{self.kind}:{self.login}" if self.login else self.kind


_bearer = HTTPBearer(
    auto_error=False,
    description="Static API token (AUTH_API_TOKEN) for CI / machine clients.",
)


def _settings(request: Request) -> Settings:
    settings: Settings = request.app.state.settings
    return settings


def current_login(request: Request) -> str | None:
    """The GitHub login from a valid session cookie, or ``None``."""
    settings = _settings(request)
    if settings.auth_session_secret is None:
        return None
    return verify_session(
        request.cookies.get(SESSION_COOKIE), settings.auth_session_secret.get_secret_value()
    )


async def require_auth(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> Principal:
    """Admit a valid session cookie or a valid static bearer; otherwise 401.

    When ``auth_required`` is off (the default) every request is admitted as anonymous,
    so the open prototype, the mock backend and the test-suite behave exactly as before.
    """
    settings = _settings(request)
    if not settings.auth_required:
        return Principal("anonymous")

    login = current_login(request)
    if login is not None:
        return Principal("session", login)

    if credentials is not None and settings.auth_api_token is not None:
        presented = credentials.credentials.encode("utf-8")
        expected = settings.auth_api_token.get_secret_value().encode("utf-8")
        if credentials.scheme.lower() == "bearer" and hmac.compare_digest(presented, expected):
            return Principal("bearer")
        log.warning("auth: rejected bearer token from %s", client_ip(request, trusted_proxy=False))

    raise HTTPException(
        status.HTTP_401_UNAUTHORIZED,
        "authentication required: sign in at /auth/github/login or send "
        "'Authorization: Bearer <AUTH_API_TOKEN>'",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def rate_limited(request: Request) -> None:
    """429 + ``Retry-After`` once this client IP has spent its token bucket."""
    settings = _settings(request)
    limiter: RateLimiter = request.app.state.rate_limiter
    wait = limiter.check(client_ip(request, trusted_proxy=settings.trusted_proxy))
    if wait > 0:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "rate limit exceeded for this client; retry later",
            headers={"Retry-After": str(max(1, math.ceil(wait)))},
        )


AuthDep = Annotated[Principal, Depends(require_auth)]
GUARDS = [Depends(rate_limited), Depends(require_auth)]
"""Dependencies for the sensitive routes: the limiter first, so a credential-stuffing flood
is throttled before any secret comparison runs."""


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


class AuthMeResponse(BaseModel):
    login: str


router = APIRouter(prefix="/auth", tags=["auth"])


def _oauth_or_503(request: Request) -> tuple[Settings, GitHubOAuth]:
    settings = _settings(request)
    oauth: GitHubOAuth | None = request.app.state.oauth
    if oauth is None or settings.auth_session_secret is None:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "GitHub sign-in is not configured on this deployment "
            "(GITHUB_OAUTH_CLIENT_ID / _SECRET / _CALLBACK_URL and AUTH_SESSION_SECRET)",
        )
    return settings, oauth


def _set_flow_cookie(response: Response, key: str, value: str, *, secure: bool) -> None:
    response.set_cookie(
        key,
        value,
        max_age=STATE_MAX_AGE_S,
        path=AUTH_COOKIE_PATH,
        secure=secure,
        httponly=True,
        samesite="lax",
    )


def _clear_flow_cookies(response: Response, *, secure: bool) -> None:
    for key in (STATE_COOKIE, NEXT_COOKIE):
        response.delete_cookie(
            key, path=AUTH_COOKIE_PATH, secure=secure, httponly=True, samesite="lax"
        )


def _flow_error(detail: str, *, status_code: int, secure: bool) -> JSONResponse:
    response = JSONResponse(
        status_code=status_code,
        content=ErrorResponse(detail=detail).model_dump(),
        headers=_NO_STORE,
    )
    _clear_flow_cookies(response, secure=secure)
    return response


@router.get(
    "/github/login",
    status_code=status.HTTP_302_FOUND,
    response_class=RedirectResponse,
    summary="Start GitHub sign-in (redirects to github.com)",
    responses={503: {"model": ErrorResponse, "description": "GitHub OAuth not configured"}},
)
async def github_login(
    request: Request,
    next_path: Annotated[
        str | None,
        Query(alias="next", max_length=2048, description="Same-origin path to return to."),
    ] = None,
) -> RedirectResponse:
    settings, oauth = _oauth_or_503(request)
    state = secrets.token_urlsafe(32)
    response = RedirectResponse(
        oauth.authorize_url(state), status_code=status.HTTP_302_FOUND, headers=_NO_STORE
    )
    _set_flow_cookie(response, STATE_COOKIE, state, secure=settings.cookie_secure)
    _set_flow_cookie(response, NEXT_COOKIE, safe_next(next_path), secure=settings.cookie_secure)
    return response


@router.get(
    "/github/callback",
    status_code=status.HTTP_303_SEE_OTHER,
    response_class=RedirectResponse,
    summary="GitHub OAuth callback (registered with the OAuth App)",
    # It makes outbound calls to GitHub, so it shares the per-IP budget of the gated routes.
    dependencies=[Depends(rate_limited)],
    responses={
        400: {"model": ErrorResponse, "description": "state mismatch or no code"},
        429: {"model": ErrorResponse, "description": "per-IP rate limit exceeded"},
        502: {"model": ErrorResponse, "description": "GitHub exchange failed"},
        503: {"model": ErrorResponse, "description": "GitHub OAuth not configured"},
    },
)
async def github_callback(
    request: Request,
    code: Annotated[str | None, Query(max_length=256)] = None,
    state: Annotated[str | None, Query(max_length=256)] = None,
    error: Annotated[str | None, Query(max_length=128)] = None,
) -> Response:
    settings, oauth = _oauth_or_503(request)
    secure = settings.cookie_secure

    expected_state = request.cookies.get(STATE_COOKIE)
    if (
        not state
        or not expected_state
        or not hmac.compare_digest(state.encode("utf-8"), expected_state.encode("utf-8"))
    ):
        log.warning("github oauth: state mismatch or missing state cookie")
        return _flow_error(
            "OAuth state mismatch or expired; start again at /auth/github/login",
            status_code=status.HTTP_400_BAD_REQUEST,
            secure=secure,
        )
    if error or not code:
        log.warning("github oauth: no code (error=%r)", error)
        return _flow_error(
            "GitHub did not return an authorization code",
            status_code=status.HTTP_400_BAD_REQUEST,
            secure=secure,
        )

    try:
        login = await run_in_threadpool(oauth.login_for_code, code)
    except OAuthExchangeError as exc:
        return _flow_error(str(exc), status_code=status.HTTP_502_BAD_GATEWAY, secure=secure)

    assert settings.auth_session_secret is not None  # _oauth_or_503 checked; for the type checker
    session = sign_session(login, settings.auth_session_secret.get_secret_value())
    response = RedirectResponse(
        safe_next(request.cookies.get(NEXT_COOKIE)),
        status_code=status.HTTP_303_SEE_OTHER,
        headers=_NO_STORE,
    )
    response.set_cookie(
        SESSION_COOKIE,
        session,
        max_age=SESSION_MAX_AGE_S,
        path="/",
        secure=secure,
        httponly=True,
        samesite="lax",
    )
    _clear_flow_cookies(response, secure=secure)
    log.info("github oauth: signed in login=%s", login)
    return response


@router.get(
    "/me",
    response_model=AuthMeResponse,
    summary="Who am I (from the session cookie)",
    responses={401: {"model": ErrorResponse, "description": "no valid session"}},
)
async def me(request: Request) -> AuthMeResponse:
    login = current_login(request)
    if login is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "not signed in")
    return AuthMeResponse(login=login)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT, summary="Clear the session")
async def logout(request: Request) -> Response:
    settings = _settings(request)
    response = Response(status_code=status.HTTP_204_NO_CONTENT, headers=_NO_STORE)
    response.delete_cookie(
        SESSION_COOKIE, path="/", secure=settings.cookie_secure, httponly=True, samesite="lax"
    )
    return response


def install_auth(app: FastAPI, settings: Settings) -> None:
    """Attach the auth state (limiter, OAuth client) and the ``/auth`` routes to ``app``."""
    app.state.rate_limiter = RateLimiter(settings.rate_limit_max, settings.rate_limit_window_s)
    app.state.oauth = build_oauth(settings)
    app.include_router(router)
    if settings.auth_required:
        log.info(
            "auth: required (session cookie or bearer); github_oauth=%s; rate limit %d/%.0fs; "
            "trusted_proxy=%s",
            "configured" if app.state.oauth is not None else "NOT configured",
            settings.rate_limit_max,
            settings.rate_limit_window_s,
            settings.trusted_proxy,
        )
