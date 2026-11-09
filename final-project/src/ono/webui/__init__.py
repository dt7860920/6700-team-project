"""Built React SPA served at ``/ui`` when ``ui_backend == "spa"``.

The ``static`` subdirectory is produced by ``frontend`` (``npm run build``, which
writes here via Vite's ``build.outDir``). It is a build artifact: ignored by git
and produced during the Docker image build, so it may be absent in a source tree
that has not been built yet.
"""

from __future__ import annotations

from pathlib import Path

STATIC_DIR = Path(__file__).parent / "static"
"""Directory holding the built SPA (index.html + assets/)."""


def spa_built() -> bool:
    """True if the SPA has been built and can be served."""
    return (STATIC_DIR / "index.html").is_file()
