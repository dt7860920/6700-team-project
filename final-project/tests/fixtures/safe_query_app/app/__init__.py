"""A PLANTED FALSE POSITIVE: the flagged line looks like a SQL sink but the query is
parameterized, so an attacker-controlled term reaches it only as a BOUND parameter, never
the SQL text. The verifier must NOT prove this (the sink runs, but the payload is not in its
dangerous argument) - it demonstrates the oracle does not false-positive.
"""
