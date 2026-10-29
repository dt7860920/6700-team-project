"""``python -m ono`` / ``ono`` - run the app with uvicorn using settings."""

from __future__ import annotations

import uvicorn

from ono.config import get_settings


def main() -> None:
    settings = get_settings()
    uvicorn.run(
        "ono.api:app",
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level.lower(),
        reload=settings.environment == "local",
    )


if __name__ == "__main__":
    main()
