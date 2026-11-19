"""Validation and metadata checks for user-selected public GitHub repositories."""

from __future__ import annotations

import hashlib
import re
from urllib.parse import urlsplit

import httpx

from ono.targets import Target

GITHUB_API = "https://api.github.com"
SUPPORTED_LANGUAGES = frozenset(
    {
        "Python",
        "JavaScript",
        "TypeScript",
        "Java",
        "Go",
        "Ruby",
        "PHP",
        "C#",
        "Kotlin",
        "Rust",
    }
)
_OWNER = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")
_REPO = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")


class SourceCheckError(ValueError):
    """A repository URL is unsafe, unavailable, private, or cannot be checked."""


def normalize_github_url(repo_url: str) -> tuple[str, str, str]:
    """Accept only canonicalizable HTTPS URLs for github.com owner/repository paths."""
    try:
        parsed = urlsplit(repo_url.strip())
        host = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise SourceCheckError("Enter a valid public GitHub repository URL.") from exc
    if (
        parsed.scheme != "https"
        or host is None
        or host.lower() != "github.com"
        or port is not None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise SourceCheckError("Only HTTPS links to github.com public repositories are allowed.")
    parts = parsed.path.strip("/").split("/")
    if len(parts) != 2:
        raise SourceCheckError("Use a repository URL like https://github.com/owner/repository.")
    owner, repo = parts
    if repo.endswith(".git"):
        repo = repo[:-4]
    if (
        not _OWNER.fullmatch(owner)
        or not _REPO.fullmatch(repo)
        or repo in {".", ".."}
        or "%" in owner
        or "%" in repo
    ):
        raise SourceCheckError("The GitHub owner or repository name is not valid.")
    canonical = f"https://github.com/{owner}/{repo}"
    clone_url = f"{canonical}.git"
    return canonical, clone_url, f"{owner}/{repo}"


def check_public_github_repo(repo_url: str, *, max_clone_mb: int) -> dict[str, object]:
    """Check public repository metadata through fixed GitHub API endpoints only."""
    canonical, clone_url, full_name = normalize_github_url(repo_url)
    api_url = f"{GITHUB_API}/repos/{full_name}"
    try:
        with httpx.Client(
            timeout=httpx.Timeout(6.0, connect=3.0),
            follow_redirects=False,
            headers={"Accept": "application/vnd.github+json", "User-Agent": "ONO-source-check"},
        ) as client:
            response = client.get(api_url)
            if response.status_code == 404:
                raise SourceCheckError("Repository not found or not public.")
            if response.status_code in (301, 302, 307, 308):
                raise SourceCheckError("Repository moved; enter its current GitHub URL.")
            if response.status_code == 403:
                raise SourceCheckError("GitHub rate limit reached; wait a little and retry.")
            response.raise_for_status()
            metadata = response.json()
            if not isinstance(metadata, dict):
                raise SourceCheckError("GitHub returned invalid repository metadata.")
            if metadata.get("private") is not False:
                raise SourceCheckError("Only public GitHub repositories can be scanned.")
            size_kb = int(metadata.get("size", 0))
            if size_kb > max_clone_mb * 1024:
                raise SourceCheckError(
                    f"GitHub reports this repository at {size_kb // 1024} MB; "
                    f"the current scan limit is {max_clone_mb} MB."
                )
            languages_response = client.get(f"{api_url}/languages")
            languages_response.raise_for_status()
            raw_languages = languages_response.json()
            if not isinstance(raw_languages, dict):
                raise SourceCheckError("GitHub returned invalid language metadata.")
    except SourceCheckError:
        raise
    except (httpx.HTTPError, ValueError, TypeError) as exc:
        raise SourceCheckError(
            "Could not check this repository with GitHub. Try again later."
        ) from exc

    languages = sorted(str(name) for name in raw_languages)
    supported = [name for name in languages if name in SUPPORTED_LANGUAGES]
    unsupported = [name for name in languages if name not in SUPPORTED_LANGUAGES]
    if not supported:
        message = (
            "No supported code language was detected; "
            "the scan may not analyze this repository."
        )
    elif unsupported:
        message = "Some repository languages are not supported and may not be analyzed."
    else:
        message = "Public repository is available for scanning."
    return {
        "repository": full_name,
        "canonical_url": canonical,
        "clone_url": clone_url,
        "default_branch": str(metadata.get("default_branch", "main")),
        "size_mb": round(size_kb / 1024, 1),
        "languages": languages,
        "supported_languages": supported,
        "unsupported_languages": unsupported,
        "scan_ready": bool(supported),
        "message": message,
    }


def target_from_public_github(repo_url: str) -> Target:
    """Resolve a GitHub URL syntactically; remote access is checked in the scan worker."""
    canonical, clone_url, repository = normalize_github_url(repo_url)
    # GitHub names this language "C#" while Semgrep names its pack "csharp".
    languages = [name.lower().replace("#", "sharp") for name in sorted(SUPPORTED_LANGUAGES)]
    target_hash = hashlib.sha256(clone_url.lower().encode()).hexdigest()[:16]
    return Target(
        target_id=f"gh-{target_hash}",
        name=repository,
        kind="repo",
        languages=languages,
        description="Public GitHub repository; scanned from a fresh shallow clone.",
        source=clone_url,
        snapshot=f"github-public:{canonical}",
    )
