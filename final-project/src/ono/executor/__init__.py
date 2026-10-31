"""The Executor: ONO's sandboxed "hands" (Deliverable 3, step 3a).

Two trust zones live in this package and the line between them is the whole point:

* **The Executor service** (:mod:`ono.executor.app`) is *privileged*: it holds the
  host Docker socket so it can spawn containers. It is deliberately small, internal
  only (never published), and token-authenticated. Nothing untrusted runs here.
* **Target containers** (:mod:`ono.executor.sandbox`) are *untrusted and jailed*:
  one ephemeral container per scan holding the ingested code, with no network,
  no capabilities, a read-only root filesystem, a non-root user, and hard CPU /
  memory / PID limits. Every operation the agents will later need (read, grep,
  patch, run, test, reset) executes *inside* that jail via ``docker exec``.

The main ONO harness never touches Docker; it talks to the Executor through
:class:`ono.executor.client.ExecutorClient`.
"""
