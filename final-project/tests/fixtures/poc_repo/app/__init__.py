"""Tiny intentionally-vulnerable, dependency-free app used by the verifier tests.

Everything is stdlib so the PoC can drive the handlers inside a bare ``python:3.x-slim``
jail (and on the host in unit tests) without installing anything.
"""
