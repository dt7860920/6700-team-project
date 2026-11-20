# Coverage corpus

Fixture repositories with **planted** vulnerabilities used to *measure* ONO's static
coverage (recall / precision), not just to exercise code paths.

* Every intended true positive is marked **on its sink line** with `# VULN: CWE-nnn` (Python)
  or `// VULN: CWE-nnn` (JS/TS). Optional tags after the CWE:
  * `regex-miss` - the pre-existing Python-only regex fallback is known to miss it;
  * `known-gap` - the threat-mapping engine is expected to miss it too (documented limit).
* Files named `clean_*` carry no markers: every flag on them is a false positive. Inside a
  marked file, a flag on an unmarked line (or with the wrong CWE) is a false positive too.

Run the measurement with `uv run scripts/coverage_eval.py` (add `--semgrep` to include the
real Semgrep engine, which needs the binary and registry access). The numbers it prints are
the ones quoted in pull requests; `tests/test_coverage_corpus.py` pins them so they cannot
regress silently.
