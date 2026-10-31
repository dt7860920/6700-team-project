"""``python -m ono`` / ``ono`` - run the app with uvicorn using settings."""

from __future__ import annotations

import uvicorn

from ono.config import get_settings


def main() -> None:
    settings = get_settings()
    reload = settings.environment == "local"
    uvicorn.run(
        "ono.api:app",
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level.lower(),
        reload=reload,
        # Only watch source, never the per-scan workspace clones (which would
        # otherwise trigger a reload storm mid-scan and restart the server).
        reload_dirs=["src"] if reload else None,
    )


if __name__ == "__main__":
    main()
