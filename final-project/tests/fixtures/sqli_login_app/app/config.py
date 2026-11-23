"""Service configuration, loaded at import time (as a real app would).

Importing this module - and therefore ``app.server`` - fails with a ``KeyError`` unless
``ACCOUNT_SECRET_KEY`` is set in the environment. A PoC must satisfy this before importing
the app (``os.environ.setdefault("ACCOUNT_SECRET_KEY", "x")``); this is the import-time
dependency that defeats a naive from-scratch script in the egress-blocked jail.
"""

import os

# Reading a mandatory secret at import time is a common production pattern and the reason a
# naive `import app` crashes before any sink is reached.
SECRET_KEY: str = os.environ["ACCOUNT_SECRET_KEY"]
