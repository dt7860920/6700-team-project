"""Scan service - the one place that enforces the allowlist and runs the pipeline.

Both the HTTP API and the Gradio UI call :class:`ScanService`, so the
authorization check cannot be bypassed by going through a different front door.

The scan is synchronous in the prototype (the response carries the findings).
``start_scan`` is already split into *create -> execute -> persist* so moving
the execute step onto a worker queue (``status="queued"`` + ``GET /scans/{id}``
polling, 202 Accepted) is a local change.
"""

from __future__ import annotations

import logging
import uuid

from ono.analyzer import BaseAnalyzer
from ono.config import Settings
from ono.errors import PipelineError
from ono.models import Finding, Scan, ScanRequest, ScanResponse, utcnow
from ono.store import ScanStore
from ono.targets import TargetRegistry

log = logging.getLogger(__name__)


class ScanService:
    def __init__(
        self,
        settings: Settings,
        registry: TargetRegistry,
        analyzer: BaseAnalyzer,
        store: ScanStore,
    ) -> None:
        self.settings = settings
        self.registry = registry
        self.analyzer = analyzer
        self.store = store

    def start_scan(self, request: ScanRequest) -> ScanResponse:
        """Authorize, run the pipeline, persist, and return the scan with findings.

        Raises:
            UnauthorizedTargetError: if ``request.target_id`` is not in the allowlist.
        """
        # 1. Allowlist gate - exact match, before anything else happens.
        target = self.registry.require(request.target_id)

        # 2. Create the scan record.
        scan_id = f"scn_{uuid.uuid4().hex[:12]}"
        created_at = utcnow()
        log.info(
            "scan %s started for target %s (backend=%s)",
            scan_id,
            target.target_id,
            self.analyzer.backend,
        )

        # 3. Execute the pipeline (synchronously for the prototype).
        findings: list[Finding] = []
        try:
            result = self.analyzer.run(scan_id, target, request.options)
        except Exception as exc:
            log.exception("scan %s failed", scan_id)
            # PipelineError carries an operator-safe reason (e.g. "executor unreachable at
            # ..."); anything else stays generic so internals never leak into the response.
            message = (
                f"analysis pipeline failed: {exc}"[:500]
                if isinstance(exc, PipelineError)
                else "analysis pipeline raised; see server logs"
            )
            scan = Scan(
                scan_id=scan_id,
                target_id=target.target_id,
                status="failed",
                model_backend=self.analyzer.backend,
                created_at=created_at,
                completed_at=utcnow(),
                message=message,
            )
            self.store.put_scan(scan, findings)
            return ScanResponse(**scan.model_dump(), findings=findings)

        findings = result.findings
        scan = Scan(
            scan_id=scan_id,
            target_id=target.target_id,
            status="done",
            model_backend=self.analyzer.backend,
            created_at=created_at,
            completed_at=utcnow(),
            findings_count=len(findings),
            pipeline=result.stages,
            message=result.summary,
        )

        # 4. Persist.
        self.store.put_scan(scan, findings)
        log.info("scan %s done: %s", scan_id, result.summary)
        return ScanResponse(**scan.model_dump(), findings=findings)

    def get_scan(self, scan_id: str) -> Scan | None:
        return self.store.get_scan(scan_id)

    def get_findings(self, scan_id: str) -> list[Finding] | None:
        return self.store.get_findings(scan_id)

    def get_finding(self, finding_id: str) -> Finding | None:
        return self.store.get_finding(finding_id)
