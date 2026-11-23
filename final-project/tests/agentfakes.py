"""Fakes for the agent / orchestrator tests: no network, no Docker, no model.

* :class:`ScriptedModel` - a :class:`~ono.agents.model.ChatModel` that replays scripted
  replies (strings under the text protocol, or ready :class:`ModelReply` objects for the
  native one) and records every request it saw.
* :class:`LocalSandbox` - a :class:`~ono.agents.tools.SandboxReader` over a local directory
  with the real jail's path rules (no absolute paths, no ``..``) and the guest's
  ``read`` / ``grep`` / ``tree`` result shapes.
* :class:`FakeExecutor` - an :class:`~ono.orchestrator.ExecutorProvider`: ``health()`` and
  the ``sandbox()`` context manager, with switches for the failure modes.
"""

from __future__ import annotations

import copy
import json
import os
import re
import shutil
import subprocess
import sys
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from ono.agents.model import CallBudget, ModelReply
from ono.config import AgentToolProtocol
from ono.executor._builder import find_manifests
from ono.executor._guest import apply_patch as guest_apply_patch
from ono.executor.client import (
    ExecutorAuthError,
    ExecutorRequestError,
    ExecutorUnavailableError,
)
from ono.executor.models import (
    ExecutorHealth,
    FileContent,
    GrepMatch,
    GrepResult,
    PatchResult,
    ProvisionResult,
    RunResult,
    SandboxInfo,
    TestRunResult,
    TreeEntry,
    TreeListing,
)
from ono.executor.sandbox import SandboxPathError, validate_rel_path

Reply = str | ModelReply
Script = Callable[[list[dict[str, Any]], list[dict[str, Any]] | None], Reply]


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


def action(tool: str, **args: Any) -> str:
    """A text-protocol action: ``{"tool": ..., "args": {...}}``."""
    return json.dumps({"tool": tool, "args": args})


def native(tool: str, args: dict[str, Any], call_id: str = "call_1") -> ModelReply:
    """A native function-calling reply (what ``ModelClient`` builds from ``tool_calls``)."""
    raw = {
        "role": "assistant",
        "content": None,
        "tool_calls": [
            {
                "id": call_id,
                "type": "function",
                "function": {"name": tool, "arguments": json.dumps(args)},
            }
        ],
    }
    reply = ModelReply(text="", protocol="native", raw_message=raw)
    from ono.agents.model import ToolCall

    reply.tool_calls = [ToolCall(name=tool, args=args, call_id=call_id)]
    return reply


def confirm_args(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "cwe": "CWE-89",
        "title": "SQL injection in /user",
        "severity": "high",
        "file": "app/views.py",
        "line_start": 16,
        "line_end": 16,
        "trace": [
            {
                "file": "app/views.py",
                "line": 13,
                "symbol": "request.args.get('id')",
                "note": "source",
            },
            {"file": "app/views.py", "line": 16, "symbol": "cur.execute(f...)", "note": "sink"},
        ],
        "confidence": 0.9,
        "description": "uid is interpolated into the SQL string.",
    }
    return {**base, **overrides}


class ScriptedModel:
    """Replays ``replies`` in order (or asks ``script`` for each turn); records requests."""

    def __init__(
        self,
        replies: list[Reply] | None = None,
        *,
        script: Script | None = None,
        protocol: AgentToolProtocol = "text",
        default: Reply | None = None,
    ) -> None:
        self._replies = list(replies or [])
        self._script = script
        self._protocol: AgentToolProtocol = protocol
        self._default = default
        self.calls: list[dict[str, Any]] = []

    @property
    def protocol(self) -> AgentToolProtocol:
        return self._protocol

    @property
    def n_calls(self) -> int:
        return len(self.calls)

    def last_messages(self) -> list[dict[str, Any]]:
        return list(self.calls[-1]["messages"])

    def chat(
        self,
        messages: list[dict[str, Any]],
        *,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.0,
        budget: CallBudget | None = None,
    ) -> ModelReply:
        if budget is not None:
            budget.take()
        self.calls.append(
            {"messages": copy.deepcopy(messages), "tools": tools, "temperature": temperature}
        )
        if self._script is not None:
            reply = self._script(messages, tools)
        elif self._replies:
            reply = self._replies.pop(0)
        elif self._default is not None:
            reply = self._default
        else:
            msg = f"ScriptedModel: script exhausted after {len(self.calls)} call(s)"
            raise AssertionError(msg)
        if isinstance(reply, str):
            return ModelReply(text=reply, protocol="text")
        out = copy.deepcopy(reply)
        if out.protocol == "native" and self._protocol == "text":
            out.protocol = "native"  # a native reply is native regardless of the default
        return out


# ---------------------------------------------------------------------------
# Sandbox + executor
# ---------------------------------------------------------------------------


class LocalSandbox:
    """Read-only sandbox over a local directory with the jail's confinement rules."""

    def __init__(self, root: Path, sandbox_id: str = "sbx_fake") -> None:
        self.root = root
        self.sandbox_id = sandbox_id
        self.calls: list[tuple[str, ...]] = []
        self.fail_with: Exception | None = None  # raised by the next operation, once

    def _maybe_fail(self) -> None:
        if self.fail_with is not None:
            exc, self.fail_with = self.fail_with, None
            raise exc

    def _resolve(self, path: str, *, allow_root: bool = False) -> Path:
        try:
            rel = validate_rel_path(path, allow_root=allow_root)
        except SandboxPathError as exc:
            raise ExecutorRequestError(422, str(exc)) from exc
        target = self.root if rel == "." else self.root / rel
        if not target.exists():
            raise ExecutorRequestError(400, f"{rel}: no such file or directory")
        return target

    def read_file(self, path: str) -> FileContent:
        self.calls.append(("read_file", path))
        self._maybe_fail()
        target = self._resolve(path)
        text = target.read_text(encoding="utf-8", errors="replace")
        total = len(text.splitlines())
        return FileContent(
            path=path,
            content=text,
            start_line=1,
            end_line=total,
            total_lines=total,
            size_bytes=target.stat().st_size,
        )

    def read_lines(self, path: str, start: int, end: int) -> FileContent:
        self.calls.append(("read_lines", path, str(start), str(end)))
        self._maybe_fail()
        target = self._resolve(path)
        lines = target.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
        chunk = lines[start - 1 : end]
        return FileContent(
            path=path,
            content="".join(chunk),
            start_line=start,
            end_line=start + len(chunk) - 1 if chunk else 0,
            total_lines=len(lines),
            size_bytes=target.stat().st_size,
        )

    def grep(
        self, pattern: str, path: str = ".", *, ignore_case: bool = False, max_matches: int = 200
    ) -> GrepResult:
        self.calls.append(("grep", pattern, path))
        self._maybe_fail()
        target = self._resolve(path, allow_root=True)
        regex = re.compile(pattern, re.IGNORECASE if ignore_case else 0)
        files = (
            [target] if target.is_file() else sorted(p for p in target.rglob("*") if p.is_file())
        )
        matches: list[GrepMatch] = []
        truncated = False
        for file in files:
            rel = file.relative_to(self.root).as_posix()
            for n, line in enumerate(file.read_text(errors="replace").splitlines(), start=1):
                if regex.search(line):
                    if len(matches) >= max_matches:
                        truncated = True
                        break
                    matches.append(GrepMatch(file=rel, line=n, text=line))
            if truncated:
                break
        return GrepResult(matches=matches, truncated=truncated, files_scanned=len(files))

    def tree(self, path: str = ".", *, max_entries: int = 2000, max_depth: int = 12) -> TreeListing:
        self.calls.append(("tree", path))
        self._maybe_fail()
        target = self._resolve(path, allow_root=True)
        entries: list[TreeEntry] = []
        truncated = False
        for p in sorted(target.rglob("*")):
            rel = p.relative_to(self.root)
            if len(rel.parts) > max_depth:
                continue
            if len(entries) >= max_entries:
                truncated = True
                break
            kind = "dir" if p.is_dir() else "file"
            entries.append(TreeEntry(path=rel.as_posix(), kind=kind, size=p.stat().st_size))
        return TreeListing(entries=entries, truncated=truncated, total=len(entries))


class LocalExecSandbox(LocalSandbox):
    """A full :class:`~ono.agents.tools.SandboxExecutor` over a local directory.

    The reads come from :class:`LocalSandbox`; the mutating operations run against a real
    temporary *working copy* of the directory, so the verifier's prover PoCs, patches and
    test runs behave like the jail without Docker. ``run`` uses ``sh -c`` with the host
    interpreter on PATH, ``apply_patch`` reuses the real in-jail diff applier, ``run_tests``
    detects pytest, and ``reset`` restores the working copy from a pristine snapshot.
    """

    def __init__(self, workspace: Path, sandbox_id: str = "sbx_fake") -> None:
        self._work = workspace
        self._pristine = workspace.parent / (workspace.name + ".pristine")
        if not self._pristine.exists():
            shutil.copytree(workspace, self._pristine)
        super().__init__(workspace, sandbox_id=sandbox_id)
        self.resets = 0
        self.runs: list[str] = []
        self.provision_result: ProvisionResult | None = None  # scripted answer, if any
        self.provision_calls = 0
        self.provision_near: list[str] = []

    def provision(
        self, timeout_s: float | None = None, *, near: list[str] | None = None
    ) -> ProvisionResult:
        """No builder offline: ``skipped`` without a manifest, ``failed`` with one (the
        honest no-deps fallback the verifier must cope with), unless scripted."""
        self.provision_calls += 1
        self.provision_near = list(near or [])
        self._maybe_fail()
        if self.provision_result is not None:
            return self.provision_result
        manifests = find_manifests(str(self.root))
        if not manifests:
            return ProvisionResult(
                status="skipped", detail="no dependency manifest in the workspace"
            )
        return ProvisionResult(
            status="failed",
            manifests=manifests,
            detail="the offline test sandbox has no builder container",
        )

    def apply_patch(self, diff: str) -> PatchResult:
        result = guest_apply_patch(str(self.root), diff)
        return PatchResult(
            applied=bool(result["applied"]),
            reason=str(result["reason"]),
            files=list(result["files"]),
        )

    def run(self, cmd: str, timeout_s: float | None = None) -> RunResult:
        self.runs.append(cmd)
        self._maybe_fail()
        start = time.perf_counter()
        timed_out = False
        # The oracle is started as `python3 -I ...` (what the jail image provides). Make sure
        # that resolves to the interpreter running the tests, whatever is first on the
        # caller's PATH (a system python3 of a different version would change the result).
        env = dict(os.environ)
        env["PATH"] = str(Path(sys.executable).parent) + os.pathsep + env.get("PATH", "")
        try:
            proc = subprocess.run(
                cmd,
                shell=True,  # a test double for the jail's `sh -c`
                cwd=self.root,
                capture_output=True,
                text=True,
                timeout=timeout_s,
                check=False,
                env=env,
            )
            stdout, stderr, code = proc.stdout, proc.stderr, proc.returncode
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            stdout = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            stderr = exc.stderr.decode() if isinstance(exc.stderr, bytes) else (exc.stderr or "")
            code = None
        return RunResult(
            cmd=cmd,
            stdout=stdout,
            stderr=stderr,
            exit_code=code,
            duration_ms=(time.perf_counter() - start) * 1000,
            timed_out=timed_out,
        )

    def run_tests(self, timeout_s: float | None = None) -> TestRunResult:
        self._maybe_fail()
        has_tests = any(self.root.rglob("test_*.py")) or any(self.root.rglob("*_test.py"))
        if not has_tests:
            return TestRunResult(
                runner="none", detected=False, passed=None, summary="no test runner detected"
            )
        command = f'"{sys.executable}" -m pytest -q -p no:cacheprovider'
        result = self.run(command, timeout_s)
        passed: bool | None
        if result.timed_out:
            passed = None
        elif result.exit_code == 0:
            passed = True
        elif result.exit_code == 5:
            passed = None
        else:
            passed = False
        tail = next((ln for ln in reversed(result.stdout.splitlines()) if ln.strip()), "")
        return TestRunResult(
            runner="pytest", command=command, detected=True, passed=passed, summary=tail, run=result
        )

    def reset(self) -> SandboxInfo:
        self.resets += 1
        shutil.rmtree(self.root)
        shutil.copytree(self._pristine, self.root)
        from datetime import UTC, datetime

        now = datetime.now(tz=UTC)
        return SandboxInfo(
            sandbox_id=self.sandbox_id,
            scan_id="scn_fake",
            status="running",
            image="fake",
            created_at=now,
            expires_at=now,
            resets=self.resets,
        )


class FakeExecExecutor:
    """Like :class:`FakeExecutor` but yields a full :class:`LocalExecSandbox` for the verifier."""

    def __init__(self, *, docker: bool = True) -> None:
        self.docker = docker
        self.events: list[str] = []
        self.sandboxes: list[LocalExecSandbox] = []
        self.runtimes: list[str] = []  # every `runtime` the verifier asked for, in order

    def health(self) -> ExecutorHealth:
        return ExecutorHealth(status="ok", docker=self.docker, active_sandboxes=0)

    @contextmanager
    def sandbox(
        self, scan_id: str, workspace_dir: Path, *, runtime: str = "python"
    ) -> Iterator[LocalExecSandbox]:
        assert workspace_dir.is_dir(), f"workspace {workspace_dir} must exist when the jail opens"
        self.runtimes.append(runtime)
        sbx = LocalExecSandbox(workspace_dir, sandbox_id=f"sbx_{scan_id}")
        self.sandboxes.append(sbx)
        self.events.append(f"create {scan_id}")
        try:
            yield sbx
        finally:
            self.events.append(f"destroy {scan_id}")


class FakeExecutor:
    """Stands in for ``ExecutorClient``: health + the per-scan sandbox context manager."""

    def __init__(
        self, *, unreachable: bool = False, docker: bool = True, auth_fail: bool = False
    ) -> None:
        self.unreachable = unreachable
        self.docker = docker
        self.auth_fail = auth_fail
        self.events: list[str] = []
        self.sandboxes: list[LocalSandbox] = []
        self.on_create: Callable[[LocalSandbox], None] | None = None

    def health(self) -> ExecutorHealth:
        if self.unreachable:
            raise ExecutorUnavailableError(
                "executor unreachable on GET /health: connection refused"
            )
        return ExecutorHealth(
            status="ok" if self.docker else "degraded", docker=self.docker, active_sandboxes=0
        )

    @contextmanager
    def sandbox(
        self, scan_id: str, workspace_dir: Path, *, runtime: str = "python"
    ) -> Iterator[LocalSandbox]:
        if self.auth_fail:
            raise ExecutorAuthError("executor rejected the token: invalid bearer token")
        assert workspace_dir.is_dir(), f"workspace {workspace_dir} must exist when the jail opens"
        sbx = LocalSandbox(workspace_dir, sandbox_id=f"sbx_{scan_id}")
        if self.on_create is not None:
            self.on_create(sbx)
        self.sandboxes.append(sbx)
        self.events.append(f"create {scan_id}")
        try:
            yield sbx
        finally:
            self.events.append(f"destroy {scan_id}")
