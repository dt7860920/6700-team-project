import os


def announce(host: str) -> int:
    return os.system("echo pinging " + host)
