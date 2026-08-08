"""Core data structures passed between the client, detectors, and reporter.

Everything a detector needs lives on ScanContext; everything a detector
produces is a Finding. Keeping this contract small is what lets new
detectors be added without touching the runner or the CLI.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def weight(self) -> int:
        return {"info": 0, "low": 1, "medium": 3, "high": 7, "critical": 12}[self.value]


@dataclass
class Tool:
    """A single tool as advertised by the MCP server's tools/list response."""
    name: str
    description: str = ""
    # MCP tool annotations (real spec fields). All optional; absent == unknown.
    read_only_hint: Optional[bool] = None
    destructive_hint: Optional[bool] = None
    idempotent_hint: Optional[bool] = None
    open_world_hint: Optional[bool] = None
    input_schema: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class Manifest:
    """Parsed .well-known/mcp.json, when present. Absence is not a failure."""
    present: bool = False
    origin: Optional[str] = None
    server_url: Optional[str] = None
    expires: Optional[str] = None
    capabilities_digest: Optional[str] = None
    signature_alg: Optional[str] = None
    signature_verified: Optional[bool] = None  # None == not yet checked
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class Finding:
    """One problem, attributable to a detector and (usually) a tool."""
    detector_id: str
    code: str                       # stable machine code, e.g. "INJ.IMPERATIVE"
    severity: Severity
    message: str
    tool_name: Optional[str] = None  # None for server/manifest-level findings
    evidence: Optional[str] = None   # the offending snippet, truncated


@dataclass
class ScanContext:
    """Everything a detector is allowed to see. Read-only by convention."""
    target: str
    tools: list[Tool]
    manifest: Manifest
    llm: Any = None  # an optional callable judge; None unless --llm passed

    # What the *source* was able to supply. A source that cannot report a
    # field is not evidence the field is empty — "the server declares no
    # annotations" and "this source strips annotations" are different facts,
    # and a detector that treats them alike reports a finding it cannot
    # support. Set False by clients that read a second-hand index rather than
    # the server itself; detectors must then say so instead of concluding.
    annotations_available: bool = True
    manifest_available: bool = True


@dataclass
class Report:
    target: str
    started_at: str
    tools_scanned: int
    findings: list[Finding]
    manifest: Manifest
    #: Every tool name the scan covered, in advertised order. Carried so that
    #: tool_scores() can report a clean tool as 0 rather than omitting it —
    #: "scanned and clean" and "not scanned" must not look identical.
    tool_names: list[str] = field(default_factory=list)
    schema_version: str = "0.1"

    def tool_scores(self) -> dict[str, int]:
        """Per-tool risk score = sum of severity weights of its findings.

        Seeded from the scanned tool set, so every tool appears. A consumer
        iterating this to rank a server's surface sees the clean tools too.
        """
        scores: dict[str, int] = {name: 0 for name in self.tool_names if name}
        for f in self.findings:
            if f.tool_name:
                scores[f.tool_name] = scores.get(f.tool_name, 0) + f.severity.weight
        return scores

    def summary(self) -> dict[str, int]:
        out = {s.value: 0 for s in Severity}
        for f in self.findings:
            out[f.severity.value] += 1
        return out
