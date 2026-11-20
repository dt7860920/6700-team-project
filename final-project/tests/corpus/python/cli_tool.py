"""Planted vulnerabilities reachable from argv / environment (CLI entry points)."""

import argparse
import os
import subprocess
import sys

import yaml


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out")
    parser.add_argument("--config")
    args = parser.parse_args()
    os.system("tar czf " + args.out + " .")  # VULN: CWE-78
    with open(args.config) as fh:  # VULN: CWE-22 regex-miss
        cfg = yaml.load(fh.read())  # VULN: CWE-502
    return 0 if cfg else 1


def run_first_argument():
    subprocess.run(sys.argv[1], shell=True)  # VULN: CWE-78


def list_dir():
    target = os.environ.get("TARGET_DIR", "/tmp")
    return os.popen(f"ls -la {target}").read()  # VULN: CWE-78


if __name__ == "__main__":
    sys.exit(main())
