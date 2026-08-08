"""Scan orchestration — the aggregation seam.

Builds the read-only ScanContext, runs every registered detector (skipping
LLM-gated ones unless --llm supplied), and assembles the Report. Adding a
detector to the registry is the only change needed to extend a scan; this
function does not name detectors individually.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable, Optional

from .detectors import REGISTRY
from .models import Finding, Manifest, Report, ScanContext, Tool


def scan(
    target: str,
    tools: list[Tool],
    manifest: Manifest,
    use_llm: bool = False,
    llm: Optional[Callable[..., Any]] = None,
    annotations_available: bool = True,
    manifest_available: bool = True,
) -> Report:
    """Run every registered detector over one server's surface.

    `annotations_available` / `manifest_available` describe what the *source*
    could supply (see `MCPClient.supports_annotations`). They default True so
    a direct scan behaves as before; a second-hand source passes False so
    detectors report "not observable from here" rather than asserting an
    absence they did not verify.
    """
    ctx = ScanContext(
        target=target,
        tools=list(tools),
        manifest=manifest,
        llm=llm if use_llm else None,
        annotations_available=annotations_available,
        manifest_available=manifest_available,
    )

    findings: list[Finding] = []
    for detector in REGISTRY:
        if getattr(detector, "requires_llm", False) and not use_llm:
            continue
        findings.extend(detector.run(ctx))

    return Report(
        target=target,
        started_at=datetime.now(timezone.utc).isoformat(),
        tools_scanned=len(ctx.tools),
        findings=findings,
        manifest=manifest,
        tool_names=[t.name for t in ctx.tools],
    )
