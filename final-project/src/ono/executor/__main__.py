"""``python -m ono.executor`` / ``ono-executor`` - run the Executor service with uvicorn.

Binds to ``executor_host:executor_port`` (loopback by default). In Compose the
service sets ``EXECUTOR_HOST=0.0.0.0`` but sits on an internal network with no
published ports; it is never reachable from outside the stack.
"""

from __future__ import annotations

import uvicorn

from ono.config import get_settings


def main() -> None:
    settings = get_settings()
    uvicorn.run(
        "ono.executor.app:get_app",
        factory=True,
        host=settings.executor_host,
        port=settings.executor_port,
        log_level=settings.log_level.lower(),
        # No reload: a reloader would re-import the app and leak the sweeper thread.
        reload=False,
    )


if __name__ == "__main__":
    main()
