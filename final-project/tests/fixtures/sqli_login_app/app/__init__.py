"""A deliberately-vulnerable stdlib-only account service used by the verifier's harder
fixtures. There is a real SQL-injection sink, but it is reachable ONLY by driving the app's
front controller: the route requires a login first, and importing the app reads a required
environment variable at load time. A PoC that calls the sink directly, skips the login or
forgets the import-time stub does not reach it - which is the point.
"""
