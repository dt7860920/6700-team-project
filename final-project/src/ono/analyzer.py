"""The analysis pipeline.

The pipeline is shaped like the real system from the project plan:

    ingest -> SAST shortlist -> plan -> analyze -> verify

Each stage is a method on :class:`BaseAnalyzer`, so the Deliverable-2
:class:`MockAnalyzer` and the future real backends share one skeleton. The mock
returns **deterministic, representative** findings per target so the API, UI,
container, and tests exercise the full request/response contract without a GPU.

Where the real system slots in (Deliverable 3):

* ``plan``    - the frozen Qwen2.5-Coder *planner* role emits a per-target scaffold.
* ``analyze`` - the Qwen *analyst* role (LangGraph ReAct loop with read_file /
                callers / grep / retrieve_cwe tools) produces candidate findings.
* ``verify``  - the deterministic verifier (plain code, no LLM) gates each
                finding and feeds failure reasons back for a bounded retry.

Both ``local`` (in-box vLLM) and ``service`` (remote OpenAI-compatible endpoint)
backends reuse the same stages; only the model client differs.
"""

from __future__ import annotations

import hashlib
import logging
import re
import time
from abc import ABC, abstractmethod
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field

from ono.config import Settings
from ono.models import Finding, ScanOptions, Severity, StageName, StageResult, TraceStep
from ono.targets import Target

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Pipeline plumbing
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Candidate:
    """A SAST-style shortlist entry handed to the agent. ``line`` is the suspected sink."""

    file: str
    line: int
    cwe_hint: str
    rule: str
    excerpt: str = ""


@dataclass(slots=True)
class Plan:
    """The adaptive per-target scaffold the planner emits (Fugu-inspired, see plan §1.5)."""

    steps: list[str]


@dataclass(slots=True)
class AnalysisResult:
    """What a pipeline run produces: verified findings plus per-stage telemetry."""

    findings: list[Finding]
    stages: list[StageResult] = field(default_factory=list)

    @property
    def summary(self) -> str:
        n = len(self.findings)
        return f"{n} verified finding{'s' if n != 1 else ''}"


def finding_id_for(target_id: str, file: str, line: int, cwe: str) -> str:
    """Stable id so the same (target, sink) yields the same finding across runs."""
    digest = hashlib.sha1(f"{target_id}|{file}|{line}|{cwe}".encode()).hexdigest()
    return f"fnd_{digest[:10]}"


class BaseAnalyzer(ABC):
    """Shared pipeline skeleton. Subclasses implement the five stages."""

    backend: str = "base"

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    # -- Orchestration ----------------------------------------------------
    def run(self, scan_id: str, target: Target, options: ScanOptions) -> AnalysisResult:
        stages: list[StageResult] = []

        with self._timed("ingest", stages) as note:
            snapshot = self.ingest(target, options)
            note(f"snapshot {snapshot}")

        with self._timed("sast", stages) as note:
            candidates = self.sast_shortlist(target, options)
            note(f"{len(candidates)} candidate(s)")

        with self._timed("plan", stages) as note:
            plan = self.plan(target, candidates)
            note(" -> ".join(plan.steps) if plan.steps else "no steps")

        with self._timed("analyze", stages) as note:
            raw = self.analyze(scan_id, target, candidates, plan)
            note(f"{len(raw)} raw finding(s)")

        with self._timed("verify", stages) as note:
            verified = self.verify(target, raw)
            note(f"{len(verified)} passed the verifier")

        findings = [f for f in verified if f.rung >= options.min_rung][: options.max_findings]
        return AnalysisResult(findings=findings, stages=stages)

    @contextmanager
    def _timed(self, stage: StageName, sink: list[StageResult]) -> Iterator[Callable[[str], None]]:
        summary = ""

        def note(text: str) -> None:
            nonlocal summary
            summary = text

        start = time.perf_counter()
        try:
            yield note
        except Exception as exc:
            elapsed = (time.perf_counter() - start) * 1000
            sink.append(
                StageResult(stage=stage, status="failed", duration_ms=elapsed, summary=str(exc))
            )
            raise
        elapsed = (time.perf_counter() - start) * 1000
        sink.append(StageResult(stage=stage, duration_ms=elapsed, summary=summary))

    # -- Stages (override in backends) -----------------------------------
    @abstractmethod
    def ingest(self, target: Target, options: ScanOptions) -> str:
        """Materialize the target snapshot; return a snapshot reference."""

    @abstractmethod
    def sast_shortlist(self, target: Target, options: ScanOptions) -> list[Candidate]:
        """Run static analysis and return the deduplicated candidate queue."""

    @abstractmethod
    def plan(self, target: Target, candidates: list[Candidate]) -> Plan:
        """Devise the per-target scaffold the analyst will execute."""

    @abstractmethod
    def analyze(
        self, scan_id: str, target: Target, candidates: list[Candidate], plan: Plan
    ) -> list[Finding]:
        """Reason over candidates and produce raw (unverified) findings."""

    @abstractmethod
    def verify(self, target: Target, findings: list[Finding]) -> list[Finding]:
        """Deterministically gate findings; return only those that pass."""


# ---------------------------------------------------------------------------
# Mock backend (Deliverable 2)
# ---------------------------------------------------------------------------

# Representative findings per target. Line numbers are plausible for the named
# projects but are illustrative: the real verifier will assert they exist.
_PYGOAT_SQLI_PATCH = """\
--- a/introduction/views.py
+++ b/introduction/views.py
@@ -207,9 +207,8 @@ def sql_lab(request):
     if request.method == "POST":
         name = request.POST.get("name")
         password = request.POST.get("pass")
-        sql_query = "SELECT * FROM introduction_login WHERE user='%s' AND password='%s'" % (name, password)
-        val = login.objects.raw(sql_query)
+        val = login.objects.filter(user=name, password=password)
         if val:
             return render(request, "Lab/SQL/sql_lab.html", {"user1": val[0].user})
"""  # noqa: E501 - verbatim diff hunk

_PYGOAT_CMDI_PATCH = """\
--- a/introduction/views.py
+++ b/introduction/views.py
@@ -468,8 +468,10 @@ def cmd_lab(request):
     if request.method == "POST":
         domain = request.POST.get("domain")
-        command = "nslookup {}".format(domain)
-        output = subprocess.check_output(command, shell=True, encoding="UTF-8")
+        if not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", domain or ""):
+            return render(request, "Lab/CMD/cmd_lab.html", {"output": "invalid domain"})
+        output = subprocess.check_output(["nslookup", domain], encoding="UTF-8")
         return render(request, "Lab/CMD/cmd_lab.html", {"output": output})
"""

_JUICE_SQLI_PATCH = """\
--- a/routes/login.ts
+++ b/routes/login.ts
@@ -34,9 +34,10 @@ module.exports = function login () {
     const email = req.body.email || ''
     const password = req.body.password || ''
-    models.sequelize.query(
-      `SELECT * FROM Users WHERE email = '${email}' AND password = '${security.hash(password)}' AND deletedAt IS NULL`,
-      { model: UserModel, plain: true })
+    models.sequelize.query(
+      'SELECT * FROM Users WHERE email = $email AND password = $password AND deletedAt IS NULL',
+      { bind: { email, password: security.hash(password) }, model: UserModel, plain: true })
       .then((authenticatedUser: { data: User }) => {
"""  # noqa: E501 - verbatim diff hunk

_JUICE_SQLI_RULE = """\
rules:
  - id: ono-juice-shop-login-sqli
    message: Template-literal SQL with request-controlled input reaches sequelize.query
    languages: [typescript, javascript]
    severity: ERROR
    metadata: { cwe: "CWE-89", ono_rung: 5 }
    patterns:
      - pattern: $DB.sequelize.query(`...${$INPUT}...`, ...)
      - metavariable-pattern:
          metavariable: $INPUT
          pattern-either:
            - pattern: req.body.$X
            - pattern: req.query.$X
"""

_FLASK_TRAVERSAL_PATCH = """\
--- a/app/files.py
+++ b/app/files.py
@@ -1,12 +1,16 @@
-import os
+from pathlib import Path
 from flask import Blueprint, abort, request, send_file

 bp = Blueprint("files", __name__)
-UPLOAD_DIR = "/srv/notes/uploads"
+UPLOAD_DIR = Path("/srv/notes/uploads").resolve()


 @bp.get("/files")
 def download():
     name = request.args.get("name", "")
-    path = os.path.join(UPLOAD_DIR, name)
-    return send_file(path)
+    path = (UPLOAD_DIR / name).resolve()
+    if not path.is_relative_to(UPLOAD_DIR) or not path.is_file():
+        abort(404)
+    return send_file(path)
"""


class MockAnalyzer(BaseAnalyzer):
    """Deterministic analyzer used for Deliverable 2 and for CI.

    No model is called and nothing is executed. Practice-app / repo targets
    return canned, realistic findings; the ``snippet`` pseudo-target runs a
    tiny regex-based "SAST" over the pasted code so the demo responds to the
    analyst's actual input.
    """

    backend = "mock"

    # -- Stage 1 ------------------------------------------------------------
    def ingest(self, target: Target, options: ScanOptions) -> str:
        # TODO(D3): clone the pinned snapshot into the egress-blocked sandbox,
        # strip .git / CVE strings, parse with tree-sitter, build the call graph.
        if target.kind == "snippet":
            size = len(options.snippet or "")
            return f"inline snippet ({size} chars)"
        return target.snapshot

    # -- Stage 2 ------------------------------------------------------------
    def sast_shortlist(self, target: Target, options: ScanOptions) -> list[Candidate]:
        # TODO(D3): Semgrep + CodeQL -> SARIF -> normalized Candidate queue.
        if target.kind == "snippet":
            return _scan_snippet(options.snippet or "")
        return [
            Candidate(file=f.file, line=f.line_range[0], cwe_hint=f.cwe, rule="mock")
            for f in _canned_findings(target.target_id, scan_id="")
        ]

    # -- Stage 3 ------------------------------------------------------------
    def plan(self, target: Target, candidates: list[Candidate]) -> Plan:
        # TODO(D3): prompt the frozen Qwen planner role to emit the scaffold.
        if not candidates:
            return Plan(steps=["ANALYZE entry-points", "REPORT none"])
        steps = [f"ANALYZE {c.file}:{c.line} ({c.cwe_hint})" for c in candidates]
        return Plan(steps=[*steps, "CHECK taint source->sink", "VERIFY patch"])

    # -- Stage 4 ------------------------------------------------------------
    def analyze(
        self, scan_id: str, target: Target, candidates: list[Candidate], plan: Plan
    ) -> list[Finding]:
        # TODO(D3): LangGraph ReAct loop over the Qwen analyst role with a hard
        # tool-call budget, backed by vLLM (local) or a remote endpoint (service).
        if target.kind == "snippet":
            return [
                _finding_from_snippet_candidate(scan_id, target.target_id, c) for c in candidates
            ]
        return _canned_findings(target.target_id, scan_id)

    # -- Stage 5 ------------------------------------------------------------
    def verify(self, target: Target, findings: list[Finding]) -> list[Finding]:
        # TODO(D3): deterministic checks - line/symbol exists, PoC reaches the
        # sink, patch applies, PoC no longer fires, tests still pass - with a
        # bounded (settings.max_verifier_retries) self-correction loop. Findings
        # that never pass are marked unverified and are NOT returned.
        return [f for f in findings if f.verified]


# ---------------------------------------------------------------------------
# Mock data
# ---------------------------------------------------------------------------


def _canned_findings(target_id: str, scan_id: str) -> list[Finding]:
    """Representative findings for the registry's non-snippet targets."""

    def make(
        *,
        title: str,
        cwe: str,
        severity: Severity,
        file: str,
        line_range: tuple[int, int],
        trace: list[TraceStep],
        confidence: float,
        rung: int,
        verified: bool,
        description: str,
        patch_diff: str,
        detection_rule: str | None = None,
    ) -> Finding:
        return Finding(
            finding_id=finding_id_for(target_id, file, line_range[0], cwe),
            scan_id=scan_id,
            target_id=target_id,
            title=title,
            cwe=cwe,
            severity=severity,
            file=file,
            line_range=line_range,
            trace=trace,
            confidence=confidence,
            rung=rung,
            verified=verified,
            description=description,
            patch_diff=patch_diff,
            detection_rule=detection_rule,
        )

    if target_id == "pygoat":
        return [
            make(
                title="SQL injection in the SQLi lab login handler",
                cwe="CWE-89",
                severity="critical",
                file="introduction/views.py",
                line_range=(210, 211),
                trace=[
                    TraceStep(
                        file="introduction/views.py",
                        line=208,
                        symbol='request.POST.get("name")',
                        note="attacker-controlled source",
                    ),
                    TraceStep(
                        file="introduction/views.py",
                        line=210,
                        symbol="sql_query (string % formatting)",
                        note="tainted value interpolated into SQL text",
                    ),
                    TraceStep(
                        file="introduction/views.py",
                        line=211,
                        symbol="login.objects.raw(sql_query)",
                        note="sink: raw SQL executed",
                    ),
                ],
                confidence=0.94,
                rung=4,
                verified=True,
                description=(
                    "User input from the login form is formatted directly into a raw SQL "
                    "string. A read-only PoC (`' OR '1'='1`) reaches the sink and returns "
                    "the first user row; after the patch the PoC no longer authenticates and "
                    "the app's tests pass."
                ),
                patch_diff=_PYGOAT_SQLI_PATCH,
            ),
            make(
                title="OS command injection in the command-injection lab",
                cwe="CWE-78",
                severity="high",
                file="introduction/views.py",
                line_range=(470, 471),
                trace=[
                    TraceStep(
                        file="introduction/views.py",
                        line=469,
                        symbol='request.POST.get("domain")',
                        note="attacker-controlled source",
                    ),
                    TraceStep(
                        file="introduction/views.py",
                        line=471,
                        symbol="subprocess.check_output(command, shell=True)",
                        note="sink: shell command built from tainted string",
                    ),
                ],
                confidence=0.88,
                rung=3,
                verified=True,
                description=(
                    "The domain field is concatenated into a shell command. PoC "
                    "`example.com; id` reaches the sink (read-only demonstration in the "
                    "sandbox). Patch validates the domain and drops shell=True."
                ),
                patch_diff=_PYGOAT_CMDI_PATCH,
            ),
        ]

    if target_id == "juice-shop":
        return [
            make(
                title="SQL injection in the login route (template-literal query)",
                cwe="CWE-89",
                severity="critical",
                file="routes/login.ts",
                line_range=(36, 38),
                trace=[
                    TraceStep(
                        file="routes/login.ts",
                        line=34,
                        symbol="req.body.email",
                        note="attacker-controlled source",
                    ),
                    TraceStep(
                        file="routes/login.ts",
                        line=37,
                        symbol="`SELECT * FROM Users WHERE email = '${email}' ...`",
                        note="tainted value interpolated into SQL",
                    ),
                    TraceStep(
                        file="routes/login.ts",
                        line=36,
                        symbol="models.sequelize.query(...)",
                        note="sink: raw query executed",
                    ),
                ],
                confidence=0.96,
                rung=5,
                verified=True,
                description=(
                    "Classic authentication bypass (`' OR 1=1--`). Patch switches to bound "
                    "parameters; a Semgrep rule is bundled to catch the pattern elsewhere."
                ),
                patch_diff=_JUICE_SQLI_PATCH,
                detection_rule=_JUICE_SQLI_RULE,
            ),
        ]

    if target_id == "flask-notes-repo":
        return [
            make(
                title="Path traversal in the file download endpoint",
                cwe="CWE-22",
                severity="high",
                file="app/files.py",
                line_range=(11, 12),
                trace=[
                    TraceStep(
                        file="app/files.py",
                        line=10,
                        symbol='request.args.get("name")',
                        note="attacker-controlled source",
                    ),
                    TraceStep(
                        file="app/files.py",
                        line=11,
                        symbol="os.path.join(UPLOAD_DIR, name)",
                        note="no canonicalization; '../' escapes the upload root",
                    ),
                    TraceStep(
                        file="app/files.py",
                        line=12,
                        symbol="send_file(path)",
                        note="sink: arbitrary file read",
                    ),
                ],
                confidence=0.91,
                rung=4,
                verified=True,
                description=(
                    "`?name=../../etc/passwd` reaches send_file. The patch resolves the path "
                    "and rejects anything outside the upload directory."
                ),
                patch_diff=_FLASK_TRAVERSAL_PATCH,
            ),
        ]

    return []


# ---------------------------------------------------------------------------
# Snippet pseudo-target: a tiny deterministic "SAST" so the demo reacts to input
# ---------------------------------------------------------------------------

_SNIPPET_RULES: tuple[tuple[str, re.Pattern[str], str, Severity], ...] = (
    (
        "CWE-89",
        re.compile(r"\.(execute|executemany|raw)\(\s*(f[\"']|[\"'].*%|.*\+\s*\w)"),
        "sql-string-built-from-input",
        "high",
    ),
    (
        "CWE-78",
        re.compile(r"(os\.system\(|subprocess\.\w+\(.*shell\s*=\s*True|os\.popen\()"),
        "shell-command-from-string",
        "high",
    ),
    (
        "CWE-95",
        re.compile(r"\b(eval|exec)\(\s*[^\"')]"),
        "eval-of-dynamic-input",
        "critical",
    ),
    (
        "CWE-502",
        re.compile(r"(pickle\.loads?\(|yaml\.load\((?!.*Loader=yaml\.SafeLoader))"),
        "unsafe-deserialization",
        "high",
    ),
)

_SNIPPET_TITLES = {
    "CWE-89": "SQL built from a dynamic string",
    "CWE-78": "Shell command built from a string",
    "CWE-95": "Dynamic code evaluation",
    "CWE-502": "Unsafe deserialization",
}

_SNIPPET_FIXES = {
    "CWE-89": "use a parameterized query: cursor.execute(sql, (param,))",
    "CWE-78": "pass an argument list and drop shell=True",
    "CWE-95": "replace eval/exec with ast.literal_eval or an explicit dispatch table",
    "CWE-502": "use json / yaml.safe_load instead of pickle or yaml.load",
}


def _scan_snippet(code: str) -> list[Candidate]:
    candidates: list[Candidate] = []
    for lineno, line in enumerate(code.splitlines(), start=1):
        for cwe, pattern, rule, _sev in _SNIPPET_RULES:
            if pattern.search(line):
                candidates.append(
                    Candidate(file="snippet.py", line=lineno, cwe_hint=cwe, rule=rule, excerpt=line)
                )
                break  # one candidate per line
    return candidates


def _finding_from_snippet_candidate(scan_id: str, target_id: str, c: Candidate) -> Finding:
    severity = next(sev for cwe, _p, _r, sev in _SNIPPET_RULES if cwe == c.cwe_hint)
    patch = (
        f"--- a/{c.file}\n+++ b/{c.file}\n"
        f"@@ -{c.line},1 +{c.line},1 @@\n"
        f"-{c.excerpt}\n"
        f"+{_indent_of(c.excerpt)}# TODO: {_SNIPPET_FIXES[c.cwe_hint]}\n"
    )
    return Finding(
        finding_id=finding_id_for(target_id, c.file, c.line, c.cwe_hint),
        scan_id=scan_id,
        target_id=target_id,
        title=_SNIPPET_TITLES[c.cwe_hint],
        cwe=c.cwe_hint,
        severity=severity,
        file=c.file,
        line_range=(c.line, c.line),
        trace=[
            TraceStep(
                file=c.file, line=c.line, symbol=c.excerpt.strip(), note=f"matched rule {c.rule}"
            )
        ],
        confidence=0.6,
        rung=2,  # mock SAST: finding + CWE + suggested patch, no proof yet
        verified=True,  # the mock verifier only checks the line exists, which it does
        description=(
            f"Pattern `{c.rule}` matched on line {c.line}. Suggested fix: "
            f"{_SNIPPET_FIXES[c.cwe_hint]}."
        ),
        patch_diff=patch,
    )


def _indent_of(line: str) -> str:
    return line[: len(line) - len(line.lstrip())]


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def build_analyzer(settings: Settings) -> BaseAnalyzer:
    """Select the analyzer backend from settings."""
    if settings.model_backend == "mock":
        return MockAnalyzer(settings)
    # TODO(D3): LocalAnalyzer (vLLM on the same box) and ServiceAnalyzer
    # (remote OpenAI-compatible endpoint, settings.model_service_url / api key).
    msg = (
        f"model_backend={settings.model_backend!r} is not implemented in the Deliverable-2 "
        "prototype; set MODEL_BACKEND=mock"
    )
    raise NotImplementedError(msg)
