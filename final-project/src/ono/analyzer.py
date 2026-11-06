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

:class:`ServiceAnalyzer` is at Deliverable 3, step 3b-1: real ``ingest`` (shallow clone
into a per-scan workspace, :mod:`ono.ingest`), a real Semgrep ``sast_shortlist``
(:mod:`ono.sast`), and an ``analyze`` stage run by the deterministic
:class:`~ono.orchestrator.DetectionOrchestrator`: one jailed sandbox per scan, then per
candidate the *planner* agent and the *analyst* ReAct loop (:mod:`ono.agents`) reading
the code through the Executor. ``verify`` is still a pass-through (step 3b-2).
"""

from __future__ import annotations

import logging
import threading
import time
from abc import ABC, abstractmethod
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Protocol

from ono import ingest, sast
from ono.agents.model import ChatModel, ModelClient, ModelError
from ono.config import Settings
from ono.errors import PipelineError
from ono.executor.client import ExecutorClient
from ono.models import (
    Finding,
    ScanOptions,
    Severity,
    StageName,
    StageResult,
    TraceStep,
    finding_id_for,
    fingerprint_for,
)
from ono.orchestrator import DetectionOrchestrator, DetectionReport, ExecutorProvider
from ono.progress import NullProgress, ProgressSink
from ono.sast import PATTERN_RULES, Candidate, scan_text
from ono.targets import Target

__all__ = [
    "AnalysisResult",
    "BaseAnalyzer",
    "Candidate",
    "Plan",
    "ServiceAnalyzer",
    "build_analyzer",
    "finding_id_for",
]

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Pipeline plumbing
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Plan:
    """The adaptive per-target scaffold the planner emits (Fugu-inspired, see plan §1.5)."""

    steps: list[str]


_SEVERITY_RANK: dict[str, int] = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def strongest_first(findings: list[Finding]) -> list[Finding]:
    """Highest rung first, then most severe; ties keep pipeline order."""
    return sorted(findings, key=lambda f: (-f.rung, _SEVERITY_RANK.get(f.severity, 9)))


@dataclass(slots=True)
class AnalysisResult:
    """What a pipeline run produces: the findings shown, plus what was left out and why.

    ``summary`` becomes the scan's ``message``, so an empty result always says *why* it is
    empty (no candidates, none confirmed, or all filtered out) instead of reading as clean.
    """

    findings: list[Finding]
    stages: list[StageResult] = field(default_factory=list)
    candidate_count: int | None = None
    below_min_rung: int = 0
    over_max_findings: int = 0
    min_rung: int = 1
    max_findings: int = 0
    notes: list[str] = field(default_factory=list)

    @property
    def summary(self) -> str:
        n = len(self.findings)
        if n:
            verified = sum(1 for f in self.findings if f.verified)
            text = f"{n} finding{'s' if n != 1 else ''} ({verified} verified)"
        elif self.below_min_rung:
            text = f"0 findings at rung >= {self.min_rung}"
        elif self.candidate_count == 0:
            text = (
                "0 findings: static analysis found no candidates; "
                "model analysis and verification were skipped"
            )
        elif self.candidate_count is not None:
            text = f"0 findings: none of the {self.candidate_count} candidate(s) was confirmed"
        else:
            text = "0 findings"
        extras: list[str] = []
        if self.below_min_rung:
            extras.append(f"{self.below_min_rung} below min_rung={self.min_rung} hidden")
        if self.over_max_findings:
            extras.append(
                f"{self.over_max_findings} more over max_findings={self.max_findings} not shown"
            )
        extras.extend(self.notes)
        return text + "".join(f"; {e}" for e in extras)


_NULL_PROGRESS = NullProgress()
_NO_CANDIDATES = "no candidates from static analysis"

StageStatus = Literal["ok", "skipped"]


class _Note(Protocol):
    def __call__(self, text: str, status: StageStatus = "ok") -> None: ...


class BaseAnalyzer(ABC):
    """Shared pipeline skeleton. Subclasses implement the five stages.

    Progress: ``run(..., progress=sink)`` binds a :class:`~ono.progress.ProgressSink` to
    the *calling thread* for the duration of the run (one analyzer instance serves
    concurrent scans on different worker threads), so any stage can call
    :meth:`report` without threading a callback through every signature.
    """

    backend: str = "base"
    verifier_enabled: bool = True
    """False while ``verify`` is a pass-through: the stage then reports itself as skipped."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._progress_local = threading.local()

    # -- Progress ---------------------------------------------------------
    @property
    def _progress(self) -> ProgressSink:
        sink: ProgressSink | None = getattr(self._progress_local, "sink", None)
        return sink if sink is not None else _NULL_PROGRESS

    @contextmanager
    def _bound_progress(self, sink: ProgressSink | None) -> Iterator[None]:
        previous: ProgressSink | None = getattr(self._progress_local, "sink", None)
        # A nested bind (ServiceAnalyzer.run -> BaseAnalyzer.run) keeps the outer sink.
        self._progress_local.sink = sink if sink is not None else previous
        try:
            yield
        finally:
            self._progress_local.sink = previous

    def report(self, message: str) -> None:
        """Tell whoever is watching what the pipeline is doing right now."""
        self._progress.step(message)

    @property
    def _options(self) -> ScanOptions:
        """The options of the scan running on this thread (defaults outside ``run``)."""
        options: ScanOptions | None = getattr(self._progress_local, "options", None)
        return options if options is not None else ScanOptions()

    def add_note(self, text: str) -> None:
        """Append a remark to this scan's summary (e.g. why analysis stopped early)."""
        notes: list[str] | None = getattr(self._progress_local, "notes", None)
        if notes is not None:
            notes.append(text)

    # -- Orchestration ----------------------------------------------------
    def run(
        self,
        scan_id: str,
        target: Target,
        options: ScanOptions,
        *,
        progress: ProgressSink | None = None,
    ) -> AnalysisResult:
        with self._bound_progress(progress):
            outer = getattr(self._progress_local, "options", None)
            self._progress_local.options = options
            if outer is None:  # a nested run (ServiceAnalyzer -> BaseAnalyzer) shares the notes
                self._progress_local.notes = []
            try:
                return self._run_stages(scan_id, target, options)
            finally:
                if outer is None:
                    self._progress_local.options = None
                    self._progress_local.notes = None

    def _run_stages(self, scan_id: str, target: Target, options: ScanOptions) -> AnalysisResult:
        stages: list[StageResult] = []

        with self._timed("ingest", stages) as note:
            self.report(
                "Preparing the pasted snippet"
                if target.kind == "snippet"
                else f"Fetching the target snapshot ({target.name})"
            )
            snapshot = self.ingest(target, options)
            note(f"snapshot {snapshot}")

        with self._timed("sast", stages) as note:
            self.report("Static analysis: building the candidate shortlist")
            candidates = self.sast_shortlist(target, options)
            note(f"{len(candidates)} candidate(s)")

        if not candidates:
            for stage in ("plan", "analyze", "verify"):
                skipped = StageResult(
                    stage=stage, status="skipped", duration_ms=0, summary=_NO_CANDIDATES
                )
                stages.append(skipped)
                self._progress.stage(skipped)
            return AnalysisResult(
                findings=[],
                stages=stages,
                candidate_count=0,
                min_rung=options.min_rung,
                max_findings=options.max_findings,
                notes=self._notes(),
            )

        with self._timed("plan", stages) as note:
            self.report(f"Planning the investigation of {len(candidates)} candidate(s)")
            plan = self.plan(target, candidates)
            note(" -> ".join(plan.steps) if plan.steps else "no steps")

        with self._timed("analyze", stages) as note:
            self.report(f"Analyzing {len(candidates)} candidate(s)")
            raw = self.analyze(scan_id, target, candidates, plan)
            note(f"{len(raw)} raw finding(s)")

        with self._timed("verify", stages) as note:
            if not raw:
                verified = []
                note("no findings to verify", status="skipped")
            elif not self.verifier_enabled:
                verified = self.verify(target, raw)
                note(
                    f"verifier not enabled yet; {len(raw)} finding(s) left unverified",
                    status="skipped",
                )
            else:
                self.report(f"Verifying {len(raw)} raw finding(s)")
                verified = self.verify(target, raw)
                passed = sum(1 for f in verified if f.verified)
                note(f"{passed} of {len(raw)} passed the verifier")

        # Filter, then keep the strongest - never just the first - under the cap.
        eligible = strongest_first([f for f in verified if f.rung >= options.min_rung])
        findings = eligible[: options.max_findings]
        return AnalysisResult(
            findings=findings,
            stages=stages,
            candidate_count=len(candidates),
            below_min_rung=len(verified) - len(eligible),
            over_max_findings=len(eligible) - len(findings),
            min_rung=options.min_rung,
            max_findings=options.max_findings,
            notes=self._notes(),
        )

    def _notes(self) -> list[str]:
        return list(getattr(self._progress_local, "notes", None) or [])

    @contextmanager
    def _timed(self, stage: StageName, sink: list[StageResult]) -> Iterator[_Note]:
        summary = ""
        outcome: StageStatus = "ok"

        def note(text: str, status: StageStatus = "ok") -> None:
            nonlocal summary, outcome
            summary, outcome = text, status

        start = time.perf_counter()
        try:
            yield note
        except Exception as exc:
            elapsed = (time.perf_counter() - start) * 1000
            failed = StageResult(
                stage=stage, status="failed", duration_ms=elapsed, summary=str(exc)
            )
            sink.append(failed)
            self._progress.stage(failed)
            raise
        elapsed = (time.perf_counter() - start) * 1000
        result = StageResult(stage=stage, status=outcome, duration_ms=elapsed, summary=summary)
        sink.append(result)
        self._progress.stage(result)

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

_VULPY_SQLI_PATCH = """\
--- a/bad/libuser.py
+++ b/bad/libuser.py
@@ -9,7 +9,10 @@ def login(username, password):
     conn.row_factory = sqlite3.Row
     c = conn.cursor()

-    user = c.execute("SELECT * FROM users WHERE username = '{}' and password = '{}'".format(username, password)).fetchone()
+    user = c.execute(
+        "SELECT * FROM users WHERE username = ? and password = ?",
+        (username, password),
+    ).fetchone()

     if user:
         return user['username']
"""  # noqa: E501 - verbatim diff hunk


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
            finding_id=finding_id_for(scan_id, target_id, file, line_range[0], cwe),
            fingerprint=fingerprint_for(target_id, file, line_range[0], cwe),
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

    if target_id == "vulpy":
        return [
            make(
                title="SQL injection in the login helper (str.format into SQL)",
                cwe="CWE-89",
                severity="critical",
                file="bad/libuser.py",
                line_range=(12, 12),
                trace=[
                    TraceStep(
                        file="bad/mod_user.py",
                        line=16,
                        symbol="request.form.get('username')",
                        note="attacker-controlled source",
                    ),
                    TraceStep(
                        file="bad/mod_user.py",
                        line=20,
                        symbol="libuser.login(username, password)",
                        note="tainted values passed through unchanged",
                    ),
                    TraceStep(
                        file="bad/libuser.py",
                        line=12,
                        symbol="c.execute(\"SELECT ... '{}'\".format(username, password))",
                        note="sink: SQL text built with str.format and executed",
                    ),
                ],
                confidence=0.93,
                rung=4,
                verified=True,
                description=(
                    "The login form's username and password are formatted straight into a "
                    "sqlite query. PoC `' OR '1'='1` authenticates as the first user; after "
                    "the patch (bound parameters) the PoC no longer logs in."
                ),
                patch_diff=_VULPY_SQLI_PATCH,
            ),
        ]

    return []


# ---------------------------------------------------------------------------
# Snippet pseudo-target: a tiny deterministic "SAST" so the demo reacts to input
# ---------------------------------------------------------------------------

# The pattern table lives in ono.sast so the service backend's regex fallback and
# the mock's snippet scanner stay one and the same.
_SNIPPET_RULES = PATTERN_RULES

_SNIPPET_TITLES = {
    "CWE-89": "SQL built from a dynamic string",
    "CWE-78": "Shell command built from a string",
    "CWE-95": "Dynamic code evaluation",
    "CWE-502": "Unsafe deserialization",
    "CWE-22": "File path built from input",
    "CWE-798": "Hard-coded secret",
    "CWE-327": "Weak hash algorithm",
}

_SNIPPET_FIXES = {
    "CWE-89": "use a parameterized query: cursor.execute(sql, (param,))",
    "CWE-78": "pass an argument list and drop shell=True",
    "CWE-95": "replace eval/exec with ast.literal_eval or an explicit dispatch table",
    "CWE-502": "use json / yaml.safe_load instead of pickle or yaml.load",
    "CWE-22": "resolve the path and check it stays inside the base directory (or use safe_join)",
    "CWE-798": "load the secret from the environment or a secrets manager",
    "CWE-327": "use hashlib.sha256 for integrity, or bcrypt / argon2 for passwords",
}


def _scan_snippet(code: str) -> list[Candidate]:
    return scan_text(code, "snippet.py")


def _finding_from_snippet_candidate(scan_id: str, target_id: str, c: Candidate) -> Finding:
    severity = next(sev for cwe, _p, _r, sev in _SNIPPET_RULES if cwe == c.cwe_hint)
    patch = (
        f"--- a/{c.file}\n+++ b/{c.file}\n"
        f"@@ -{c.line},1 +{c.line},1 @@\n"
        f"-{c.excerpt}\n"
        f"+{_indent_of(c.excerpt)}# TODO: {_SNIPPET_FIXES[c.cwe_hint]}\n"
    )
    return Finding(
        finding_id=finding_id_for(scan_id, target_id, c.file, c.line, c.cwe_hint),
        fingerprint=fingerprint_for(target_id, c.file, c.line, c.cwe_hint),
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
# Service backend (Deliverable 3, step 3b-1: the agentic detection core)
# ---------------------------------------------------------------------------
#
# The model is called through an OpenAI-compatible ``/chat/completions`` endpoint
# (the team runs Ollama at http://localhost:11434/v1 with ``qwen2.5-coder:7b``).
# Shape of a run:
#
#   preflight - the Executor must answer /health (and see Docker) or the scan fails
#               with an actionable message before anything is cloned
#   ingest    - clone / copy / write the target into <workspace_dir>/<scan_id>/ (host)
#   sast      - Semgrep (regex fallback) over that directory -> bounded Candidate queue
#   plan      - deterministic: the queue the orchestrator will walk (the LLM planner
#               runs per candidate inside ``analyze``)
#   analyze   - ``DetectionOrchestrator.detect``: ONE jailed sandbox for the scan, then
#               per candidate planner -> analyst ReAct loop (read-only sandbox tools) ->
#               anchored Finding or dismissal. All target-code reads go through the jail.
#   verify    - pass-through (the graded verifier is step 3b-2)
#
# The workspace is removed when the run ends, success or failure.


class ServiceAnalyzer(BaseAnalyzer):
    """Planner + analyst agents on a remote OpenAI-compatible endpoint, reading through the jail.

    Findings are model-asserted (``verified=False``) and capped at rung 2 (CWE plus an
    evidence-anchored source->sink trace); nothing is executed or proven until 3b-2.
    """

    backend = "service"
    verifier_enabled = False  # TODO(3b-2): the graded verifier

    def __init__(
        self,
        settings: Settings,
        *,
        model: ChatModel | None = None,
        executor: ExecutorProvider | None = None,
    ) -> None:
        super().__init__(settings)
        if not settings.model_service_url:  # Settings already validates this; be explicit.
            msg = "ServiceAnalyzer requires settings.model_service_url"
            raise ValueError(msg)
        self.base_url = settings.model_service_url.rstrip("/")
        self.model: ChatModel = model if model is not None else ModelClient(settings)
        if executor is None:
            if settings.executor_token is None or not settings.executor_token.get_secret_value():
                msg = (
                    "ServiceAnalyzer requires settings.executor_token: the agents read target "
                    "code only through the Executor sandbox (set EXECUTOR_TOKEN)"
                )
                raise ValueError(msg)
            executor = ExecutorClient(
                settings.executor_url,
                settings.executor_token.get_secret_value(),
                max_archive_bytes=settings.max_clone_mb * 1_000_000,
            )
        self.executor: ExecutorProvider = executor
        self.orchestrator = DetectionOrchestrator(settings, model=self.model, executor=executor)
        self.last_report: DetectionReport | None = None
        # ``run`` executes all stages on one thread, so the workspace path can travel
        # from ``ingest`` to ``analyze`` in a thread-local without cross-scan leakage.
        self._local = threading.local()

    # -- Orchestration ----------------------------------------------------
    def run(
        self,
        scan_id: str,
        target: Target,
        options: ScanOptions,
        *,
        progress: ProgressSink | None = None,
    ) -> AnalysisResult:
        self._local.workspace = ingest.workspace_path(self.settings.workspace_dir, scan_id)
        try:
            with self._bound_progress(progress):
                # Fail fast: an unreachable Executor fails the scan *before* cloning
                # anything, with a message the API surfaces - never a silent fallback to
                # host reads.
                self.report("Checking the sandbox Executor and the model endpoint")
                health = self.orchestrator.preflight()
                self._check_model()
                log.info(
                    "service backend: executor ok (%d active sandbox(es)); model %s via %s",
                    health.active_sandboxes,
                    self.settings.model_name,
                    self.base_url,
                )
                return super().run(scan_id, target, options)
        finally:
            # The clone is a copy we never keep: remove it whether or not the run succeeded.
            ingest.cleanup_workspace(self._local.workspace)
            self._local.workspace = None

    def _check_model(self) -> None:
        """Fail before cloning if the model endpoint is down (it used to fail mid-analysis)."""
        probe = getattr(self.model, "health", None)  # test doubles may not implement it
        if not callable(probe):
            return
        try:
            probe()
        except ModelError as exc:
            msg = f"the model service is not available ({exc}); no stage was run"
            raise PipelineError(msg) from exc

    @property
    def _workspace(self) -> Path:
        workspace: Path | None = getattr(self._local, "workspace", None)
        if workspace is None:  # a stage was called outside ``run``
            msg = "ServiceAnalyzer stages must run via run(); no workspace is set"
            raise RuntimeError(msg)
        return workspace

    # -- Stage 1 ------------------------------------------------------------
    def ingest(self, target: Target, options: ScanOptions) -> str:
        # TODO(D3): run the clone inside the egress-blocked sandbox container and strip
        # CVE strings; tree-sitter parse + call graph. For now: shallow clone into the
        # local workspace, .git removed, nothing executed.
        root = ingest.ingest_target(
            target,
            options,
            workspace=self._workspace,
            clone_timeout_s=self.settings.clone_timeout_s,
            max_clone_mb=self.settings.max_clone_mb,
        )
        return str(root)

    # -- Stage 2 ------------------------------------------------------------
    def sast_shortlist(self, target: Target, options: ScanOptions) -> list[Candidate]:
        # TODO(D3): add CodeQL -> SARIF alongside Semgrep; union with entry points.
        result = sast.shortlist(
            self._workspace,
            rulesets=self.settings.sast_ruleset.split(","),
            languages=target.languages,
            max_candidates=self.settings.max_candidates,
        )
        log.info(
            "service backend: sast engine=%s (%s) -> %d candidate(s) for %s",
            result.engine,
            result.note,
            len(result.candidates),
            target.target_id,
        )
        if result.engine == "regex" and self.settings.sast_ruleset.strip():
            self.add_note(
                "Semgrep was unavailable, so only the built-in patterns ran (reduced coverage)"
            )
        if result.trimmed:
            self.add_note(
                f"{result.trimmed} more SAST candidate(s) beyond "
                f"max_candidates={self.settings.max_candidates} were not analyzed"
            )
        return result.candidates

    # -- Stage 3 ------------------------------------------------------------
    def plan(self, target: Target, candidates: list[Candidate]) -> Plan:
        # The target-level plan is the deterministic queue the orchestrator walks. The
        # LLM *planner agent* runs per candidate inside ``analyze`` (its plan feeds the
        # analyst directly), so this stage makes no model call.
        if not candidates:
            return Plan(steps=["REPORT none (no SAST candidates)"])
        mode = "planner+analyst" if self.settings.planner_enabled else "analyst"
        queue = candidates[: self.settings.max_candidates]
        return Plan(steps=[f"{mode} {c.file}:{c.line} ({c.cwe_hint})" for c in queue])

    # -- Stage 4 ------------------------------------------------------------
    def analyze(
        self, scan_id: str, target: Target, candidates: list[Candidate], plan: Plan
    ) -> list[Finding]:
        options = self._options
        report = self.orchestrator.detect(
            scan_id,
            target.target_id,
            self._workspace,
            candidates,
            progress=self.report,
            stop_after=options.max_findings,
            min_rung=options.min_rung,
            target_kind=target.kind,
        )
        self.last_report = report
        if report.not_reviewed:
            self.add_note(
                f"stopped after max_findings={options.max_findings}; "
                f"{report.not_reviewed} candidate(s) not reviewed"
            )
        log.info("service backend: %s", report.summary)
        return report.findings

    # -- Stage 5 ------------------------------------------------------------
    def verify(self, target: Target, findings: list[Finding]) -> list[Finding]:
        # TODO(3b-2): the graded verifier (line/symbol exists, PoC reaches the sink, patch
        # applies, PoC no longer fires, tests pass) with a bounded self-correction loop.
        # Until then this is a pass-through: findings stay verified=False.
        return findings


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def build_analyzer(settings: Settings) -> BaseAnalyzer:
    """Select the analyzer backend from settings."""
    if settings.model_backend == "mock":
        return MockAnalyzer(settings)
    if settings.model_backend == "service":
        return ServiceAnalyzer(settings)
    # TODO(D3): LocalAnalyzer - the same pipeline against an in-box vLLM.
    msg = (
        f"model_backend={settings.model_backend!r} is not implemented yet; "
        "set MODEL_BACKEND=mock or MODEL_BACKEND=service"
    )
    raise NotImplementedError(msg)
