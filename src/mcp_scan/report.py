"""Report rendering — the two output formats.

`to_json` is the machine contract a CI Action consumes; its shape is pinned
by schema/report.schema.json (top-level keys are a closed set). `to_table`
is the human view. Both read a Report; neither mutates it.
"""
from __future__ import annotations

import json

from .models import Report, Severity

# Worst-first, for stable human ordering.
_SEV_RANK = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


def to_json(report: Report) -> str:
    m = report.manifest
    payload = {
        "schema_version": report.schema_version,
        "target": report.target,
        "started_at": report.started_at,
        "tools_scanned": report.tools_scanned,
        "summary": report.summary(),
        "tool_scores": report.tool_scores(),
        "manifest": {
            "present": m.present,
            "origin": m.origin,
            "server_url": m.server_url,
            "signature_verified": m.signature_verified,
        },
        "findings": [
            {
                "detector_id": f.detector_id,
                "code": f.code,
                "severity": f.severity.value,
                "tool_name": f.tool_name,
                "message": f.message,
                "evidence": f.evidence,
            }
            for f in report.findings
        ],
    }
    return json.dumps(payload, indent=2)


def to_table(report: Report) -> str:
    lines: list[str] = []
    lines.append(f"MCP trust scan — {report.target}")
    lines.append(f"  tools scanned: {report.tools_scanned}")

    summary = report.summary()
    summary_str = "  ".join(
        f"{sev.value}={summary[sev.value]}"
        for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)
    )
    lines.append(f"  findings: {summary_str}")
    lines.append("")

    if not report.findings:
        lines.append("  no findings — no known poisoning patterns or declared/actual contradictions.")
        lines.append("  (a clean scan is the absence of known shapes, not a safety guarantee.)")
        return "\n".join(lines)

    ordered = sorted(report.findings, key=lambda f: _SEV_RANK.get(f.severity, 99))
    width = max(len(f.severity.value) for f in ordered)
    for f in ordered:
        sev = f.severity.value.upper().ljust(width)
        scope = f.tool_name or "<server>"
        lines.append(f"  [{sev}] {f.code}  ({scope})")
        lines.append(f"          {f.message}")
        if f.evidence:
            lines.append(f"          evidence: {f.evidence}")
    return "\n".join(lines)
