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

:class:`ServiceAnalyzer` is at Deliverable 3, step 2: real ``ingest`` (shallow clone
into a per-scan workspace, :mod:`ono.ingest`) and a real Semgrep ``sast_shortlist``
(:mod:`ono.sast`) feed the model real file context per candidate. ``plan`` is still
a fixed step list and ``verify`` is still a pass-through.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import threading
import time
from abc import ABC, abstractmethod
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from ono import ingest, sast
from ono.config import Settings
from ono.models import Finding, ScanOptions, Severity, StageName, StageResult, TraceStep
from ono.sast import PATTERN_RULES, Candidate, scan_text
from ono.targets import Target

__all__ = ["AnalysisResult", "BaseAnalyzer", "Candidate", "Plan", "build_analyzer"]

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Pipeline plumbing
# ---------------------------------------------------------------------------


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
}

_SNIPPET_FIXES = {
    "CWE-89": "use a parameterized query: cursor.execute(sql, (param,))",
    "CWE-78": "pass an argument list and drop shell=True",
    "CWE-95": "replace eval/exec with ast.literal_eval or an explicit dispatch table",
    "CWE-502": "use json / yaml.safe_load instead of pickle or yaml.load",
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
# Service backend (Deliverable 3, step 2: real ingest + Semgrep shortlist)
# ---------------------------------------------------------------------------
#
# The model is called through an OpenAI-compatible ``/chat/completions`` endpoint
# (the team runs Ollama at http://localhost:11434/v1 with ``qwen2.5-coder:7b``).
# Shape of a run:
#
#   ingest  - clone / copy / write the target into <workspace_dir>/<scan_id>/
#   sast    - Semgrep (regex fallback) over that directory -> bounded Candidate queue
#   analyze - ONE model call per candidate, over the real code around the sink;
#             the model confirms or dismisses and the Finding is anchored to the
#             candidate's real file:line
#   verify  - pass-through (the deterministic verifier is the next step)
#
# The workspace is removed when the run ends, success or failure.

_MODEL_TIMEOUT_S = 120.0

_SYSTEM_PROMPT = (
    "You are a senior application-security reviewer. You find real, exploitable security "
    "vulnerabilities in source code and respond ONLY with strict JSON - no prose, no "
    "markdown fences, no comments."
)

_CANDIDATE_PROMPT = """\
A static-analysis tool flagged a possible vulnerability. Decide whether it is a GENUINE,
exploitable issue by reading the surrounding code. Do not pad: if the flagged code is
safe (input is validated, constant, or unreachable), dismiss it.

Flag:
  file: {file}
  line: {line}
  suspected CWE: {cwe_hint}
  rule: {rule}

Respond with ONE JSON object with exactly these keys:
  "vulnerable": true or false
  "cwe": string such as "CWE-89" (your best classification; may differ from the hint)
  "title": short string
  "severity": one of "low", "medium", "high", "critical"
  "file": "{file}"
  "line_start": integer, 1-based line of the vulnerable sink as numbered below
  "line_end": integer >= line_start
  "description": why this is exploitable and how (or why it is safe if dismissed)
  "suggested_patch": a unified diff (or minimal corrected code) that fixes it; "" if dismissed
  "confidence": number between 0 and 1

File: {file}, lines {first}-{last} (each line is shown as "N | code"; the "N |" prefix is
not part of the code; the flagged line is marked with ">>")
```
{numbered_code}
```
"""

_SNIPPET_FILE = ingest.SNIPPET_FILE
_JSON_FENCE = re.compile(r"```(?:json|JSON)?\s*(.*?)```", re.DOTALL)
_CWE_NUMBER = re.compile(r"(\d+)")
_SEVERITY_ALIASES: dict[str, Severity] = {
    "low": "low",
    "info": "low",
    "informational": "low",
    "medium": "medium",
    "moderate": "medium",
    "high": "high",
    "critical": "critical",
}


class ServiceAnalyzer(BaseAnalyzer):
    """Calls a remote OpenAI-compatible endpoint over real, SAST-shortlisted code.

    Step 2 of Deliverable 3. Findings are model-asserted (``verified=False``) and
    capped at rung 2 because nothing has proven them yet.
    """

    backend = "service"

    def __init__(self, settings: Settings) -> None:
        super().__init__(settings)
        if not settings.model_service_url:  # Settings already validates this; be explicit.
            msg = "ServiceAnalyzer requires settings.model_service_url"
            raise ValueError(msg)
        self.base_url = settings.model_service_url.rstrip("/")
        # One long-lived client (connection reuse). Tests swap in httpx.MockTransport.
        self._http = httpx.Client(timeout=_MODEL_TIMEOUT_S)
        # ``run`` executes all stages on one thread, so the workspace path can travel
        # from ``ingest`` to ``analyze`` in a thread-local without cross-scan leakage.
        self._local = threading.local()

    # -- Orchestration ----------------------------------------------------
    def run(self, scan_id: str, target: Target, options: ScanOptions) -> AnalysisResult:
        self._local.workspace = ingest.workspace_path(self.settings.workspace_dir, scan_id)
        try:
            return super().run(scan_id, target, options)
        finally:
            # The clone is a copy we never keep: remove it whether or not the run succeeded.
            ingest.cleanup_workspace(self._local.workspace)
            self._local.workspace = None

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
        return result.candidates

    # -- Stage 3 ------------------------------------------------------------
    def plan(self, target: Target, candidates: list[Candidate]) -> Plan:
        # TODO(D3): prompt the frozen Qwen planner role to emit the scaffold.
        if not candidates:
            return Plan(steps=["REPORT none (no SAST candidates)"])
        return Plan(steps=[f"CONFIRM {c.file}:{c.line} ({c.cwe_hint})" for c in candidates])

    # -- Stage 4 ------------------------------------------------------------
    def analyze(
        self, scan_id: str, target: Target, candidates: list[Candidate], plan: Plan
    ) -> list[Finding]:
        # TODO(D3): LangGraph ReAct loop over the Qwen analyst role with a hard
        # tool-call budget. Step 2 is one direct call per candidate over the real
        # code around the sink; findings are anchored to the candidate's file:line.
        root = self._workspace
        findings: list[Finding] = []
        seen_ids: set[str] = set()
        for c in candidates[: self.settings.max_candidates]:  # hard bound on model calls
            window = _read_context(root, c, self.settings.context_lines)
            if window is None:
                log.warning("service backend: cannot read %s:%d; skipping", c.file, c.line)
                continue
            first, numbered = window
            messages = [
                {"role": "system", "content": _SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": _CANDIDATE_PROMPT.format(
                        file=c.file,
                        line=c.line,
                        cwe_hint=c.cwe_hint or "unknown",
                        rule=c.rule,
                        first=first,
                        last=first + numbered.count("\n"),
                        numbered_code=numbered,
                    ),
                },
            ]
            content = self.chat(messages)
            items = _parse_model_findings(content)
            if not items:
                log.info("service backend: unparseable reply for %s:%d; skipped", c.file, c.line)
            for item in items:
                if _is_dismissed(item):
                    log.info("service backend: model dismissed %s:%d (%s)", c.file, c.line, c.rule)
                    continue
                finding = _finding_from_model_item(
                    scan_id, target.target_id, item, anchor=c, window=(first, numbered)
                )
                if finding is not None and finding.finding_id not in seen_ids:
                    seen_ids.add(finding.finding_id)
                    findings.append(finding)
        return findings

    # -- Stage 5 ------------------------------------------------------------
    def verify(self, target: Target, findings: list[Finding]) -> list[Finding]:
        # TODO(D3, NEXT STEP): deterministic verifier (line/symbol exists, PoC reaches
        # the sink, patch applies, PoC no longer fires, tests pass) with a bounded
        # self-correction loop. Until then this is a pass-through: verified=False.
        return findings

    # -- Model client -------------------------------------------------------
    def chat(self, messages: list[dict[str, str]]) -> str:
        """One ``/chat/completions`` round-trip; returns the assistant message text.

        Transport errors (connection refused, 5xx, timeout) propagate so the scan is
        reported as *failed* rather than silently "clean".
        """
        payload: dict[str, object] = {
            "model": self.settings.model_name,
            "messages": messages,
            "temperature": 0,
            "stream": False,
        }
        headers: dict[str, str] = {}
        if self.settings.model_service_api_key is not None:
            key = self.settings.model_service_api_key.get_secret_value()
            headers["Authorization"] = f"Bearer {key}"
        response = self._http.post(
            f"{self.base_url}/chat/completions", json=payload, headers=headers
        )
        response.raise_for_status()
        try:
            content = response.json()["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            msg = "model endpoint returned an unexpected chat-completions body"
            raise ValueError(msg) from exc
        return content if isinstance(content, str) else ""


def _parse_model_findings(text: str) -> list[dict[str, object]]:
    """Extract the list of finding dicts from the model's reply.

    Tolerates markdown fences, surrounding prose, and a top-level object instead
    of a list. Returns ``[]`` (with a warning) on anything unparseable.
    """
    candidates: list[str] = [m.strip() for m in _JSON_FENCE.findall(text)]
    stripped = text.strip()
    candidates.append(stripped)
    # Fall back to the outermost bracketed region, for prose around bare JSON.
    for open_ch, close_ch in (("[", "]"), ("{", "}")):
        start, end = stripped.find(open_ch), stripped.rfind(close_ch)
        if start != -1 and end > start:
            candidates.append(stripped[start : end + 1])

    for blob in candidates:
        if not blob:
            continue
        try:
            data = json.loads(blob)
        except ValueError:
            continue
        items = _coerce_to_item_list(data)
        if items is not None:
            return items

    log.warning("service backend: could not parse model output as JSON findings; dropping it")
    log.debug("unparseable model output: %r", text[:2000])
    return []


def _coerce_to_item_list(data: object) -> list[dict[str, object]] | None:
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        for key in ("findings", "vulnerabilities", "results", "issues"):
            inner = data.get(key)
            if isinstance(inner, list):
                return [item for item in inner if isinstance(item, dict)]
        if "cwe" in data:  # the model returned a single finding object
            return [data]
        if not data:
            return []
    return None


def _read_context(root: Path, c: Candidate, context_lines: int) -> tuple[int, str] | None:
    """Numbered code around the candidate sink: ``(first_line_number, numbered_text)``.

    Lines are rendered as ``"N | code"`` with the flagged line marked ``">>"``. Returns
    ``None`` when the file cannot be read (gone, binary, or outside the workspace).
    """
    path = (root / c.file).resolve()
    try:
        if not path.is_relative_to(root.resolve()):  # a crafted path must never escape
            return None
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    if not lines:
        return None
    first = max(1, c.line - context_lines)
    last = min(len(lines), c.line + context_lines)
    numbered = "\n".join(
        f"{'>>' if i == c.line else '  '}{i:5d} | {lines[i - 1]}" for i in range(first, last + 1)
    )
    return first, numbered


def _is_dismissed(item: dict[str, object]) -> bool:
    """``{"vulnerable": false}`` (or string equivalents) means the model rejected the flag."""
    value = item.get("vulnerable", True)
    if isinstance(value, bool):
        return not value
    return str(value).strip().lower() in {"false", "no", "0", "none"}


def _finding_from_model_item(
    scan_id: str,
    target_id: str,
    item: dict[str, object],
    *,
    anchor: Candidate | None = None,
    window: tuple[int, str] | None = None,
) -> Finding | None:
    """Map one model-emitted dict onto :class:`Finding`; ``None`` if unusable.

    With an ``anchor`` candidate, the finding is pinned to the candidate's real file and
    the model's line numbers are honoured only if they fall inside the code ``window`` it
    was shown; otherwise the sink line is the candidate's. A one-hop trace records the
    SAST rule that surfaced the sink.
    """
    cwe_match = _CWE_NUMBER.search(str(item.get("cwe", "")))
    if cwe_match is None:
        log.warning("service backend: dropping finding without a CWE: %r", item.get("title"))
        return None
    cwe = f"CWE-{cwe_match.group(1)}"

    severity = _SEVERITY_ALIASES.get(str(item.get("severity", "")).strip().lower(), "medium")
    reported_start = _as_int(item.get("line_start", item.get("line")), default=0)
    line_start = max(1, reported_start) if reported_start else 1
    line_end = max(line_start, _as_int(item.get("line_end"), default=line_start))
    trace: list[TraceStep] = []
    if anchor is not None:
        file = anchor.file
        if window is not None and (first := window[0]) <= reported_start <= (
            last := first + window[1].count("\n")
        ):
            line_end = min(line_end, last)  # the model's lines, as long as it saw them
        else:
            line_start, line_end = anchor.line, anchor.line
        trace.append(
            TraceStep(
                file=anchor.file,
                line=anchor.line,
                symbol=anchor.excerpt.strip() or f"line {anchor.line}",
                note=f"sink flagged by SAST rule {anchor.rule}",
            )
        )
    else:
        file = str(item.get("file") or _SNIPPET_FILE)
    confidence = min(1.0, max(0.0, _as_float(item.get("confidence"), default=0.5)))
    patch = str(item.get("suggested_patch") or "")
    title = str(item.get("title") or f"{cwe} reported by {target_id} model analysis")

    return Finding(
        finding_id=finding_id_for(target_id, file, line_start, cwe),
        scan_id=scan_id,
        target_id=target_id,
        title=title,
        cwe=cwe,
        severity=severity,
        file=file,
        line_range=(line_start, line_end),
        trace=trace,  # no source->sink flow yet: just the SAST-flagged sink
        confidence=confidence,
        # Rung 2 = finding + CWE + suggested patch, model-asserted. Without a patch the
        # ladder only supports rung 1 (bare flag). Nothing is proven until the verifier.
        rung=2 if patch else 1,
        verified=False,
        description=str(item.get("description") or ""),
        patch_diff=patch,
    )


def _as_int(value: object, *, default: int) -> int:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return default


def _as_float(value: object, *, default: float) -> float:
    try:
        return float(str(value))
    except (TypeError, ValueError):
        return default


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
