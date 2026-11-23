#!/usr/bin/env python
"""Django management entry point - marks the repository ROOT as a Django project, exactly as
pygoat's does. It is never imported by the verifier; it only makes the root manifest's Django
the obvious (and wrong) thing to provision for the nested Flask lab."""

import os
import sys


def main() -> None:
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "project.settings")
    from django.core.management import execute_from_command_line

    execute_from_command_line(sys.argv)


if __name__ == "__main__":
    main()
