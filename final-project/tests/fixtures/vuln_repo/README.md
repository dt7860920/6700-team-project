# vuln_repo (test fixture)

A two-file, intentionally vulnerable sample "repository" that the ONO tests ingest
from a local path (no network, no git). Sinks:

- `app/views.py:16` SQL built with an f-string (CWE-89)
- `app/views.py:23` `os.system` with concatenated input (CWE-78)
- `app/util.py:5` `pickle.loads` on untrusted bytes (CWE-502)
