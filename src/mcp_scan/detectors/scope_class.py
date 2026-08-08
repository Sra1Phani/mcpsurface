"""Declared-vs-actual capability mismatch.

MCP lets a tool annotate itself read_only / non-destructive. An agent's
consent policy keys off those hints. So a tool that *describes* an
irreversible action (delete, transfer, pay, deploy) while *declaring*
itself read-only is either sloppy or hostile — either way it can slip
past a consent gate that trusted the annotation.

This detector compares the verbs in the description against the declared
hints and flags the contradiction.
"""
from __future__ import annotations

import re

from .base import Detector
from ..models import Finding, ScanContext, Severity
from ..text import normalize

# Verbs implying a side effect / irreversible or financial action.
# Inter-word gaps are `\s+`, never a literal space, and the description is
# normalized before matching — otherwise "send  money" (two spaces) or a
# homoglyph slips a mutating tool past the annotation cross-check.
_SIDE_EFFECT = re.compile(
    r"\b(?:delete|remove|destroy|wipe|transfer|send\s+(?:money|funds|payment)|"
    r"pay|buy|charge|refund|withdraw|deploy|grant|revoke|"
    r"overwrite|reset"
    # CORPUS-CALIBRATED, all four qualified rather than dropped:
    #   "execute"  — "Execute a read-only SQL SELECT query" is a read. Only an
    #                executable *thing* implies a side effect, not a query.
    #   "drop"     — matched inside "drop-down values" and "Drop a pin in Apple
    #                Maps". Require a database object.
    #   purchase/  — appeared as nouns ("Purchase" as a voucher category, a
    #   publish       "publish" mention in a list tool). Require an object.
    r"|execute\s+(?:a\s+|an\s+|the\s+)?(?:arbitrary\s+)?"
    r"(?:command|script|shell|code|program|binary|mutation)"
    r"|run\s+command"
    r"|drop\s+(?:the\s+)?(?:table|index|database|collection|column|schema|view)"
    r"|(?:purchase|publish)\s+(?:the|a|an|this|to)\b"
    r")\b",
    re.IGNORECASE,
)

# A description that asserts its own read-only-ness, or explicitly disclaims the
# mutation it mentions, is not contradicting its annotation — it is agreeing
# with it in prose the verb match cannot see.
#
# CORPUS-CALIBRATED. These phrases produced most of the remaining false
# contradictions: "Execute a read-only SQL SELECT query", "Install/remove not
# available via MCP — use CLI", "BLOCKED: Destructive commands", "For writes,
# use execute_rest_write". Matching a verb somewhere in a paragraph and
# concluding the tool mutates ignores the sentence that says it doesn't.
_DISCLAIMS_MUTATION = re.compile(
    r"read[-\s]only|only\s+SELECT|\bGET\s+request|not\s+available|"
    r"\bblocked\b|for\s+writes[,\s]|is\s+disabled|no\s+(?:writes|mutations)|"
    r"does\s+not\s+(?:modify|delete|remove|write|change)|"
    r"without\s+(?:modifying|deleting|changing)",
    re.IGNORECASE,
)


class ScopeClassDetector(Detector):
    id = "scope_class"
    title = "Declared annotation vs. described behavior"

    def run(self, ctx: ScanContext) -> list[Finding]:
        out: list[Finding] = []

        if not ctx.annotations_available:
            # The source strips annotations, so every tool would look
            # unannotated and every contradiction check would be vacuous.
            # Say that once, plainly, instead of emitting a finding per tool
            # that reads as a fact about the server.
            return [Finding(
                detector_id=self.id, code="SCOPE.ANNOTATIONS_UNAVAILABLE",
                severity=Severity.INFO,
                message="This source does not report MCP tool annotations, so "
                        "declared-vs-actual capability checks did not run. This "
                        "is a limit of the source, not a statement that the "
                        "server declares nothing.",
            )]

        for tool in ctx.tools:
            desc = normalize(tool.description or "")
            m = _SIDE_EFFECT.search(desc)
            if not m:
                continue
            if _DISCLAIMS_MUTATION.search(desc):
                continue        # the prose already says it doesn't mutate
            verb = m.group(0)

            # Claims read-only but describes a mutation.
            if tool.read_only_hint is True:
                out.append(Finding(
                    detector_id=self.id, code="SCOPE.READONLY_MISMATCH",
                    severity=Severity.HIGH, tool_name=tool.name, evidence=verb,
                    message=f"Tool declares read_only_hint=true but its description "
                            f"implies a side effect ('{verb}').",
                ))

            # Describes a destructive action but doesn't flag it as destructive.
            if tool.destructive_hint is False:
                out.append(Finding(
                    detector_id=self.id, code="SCOPE.DESTRUCTIVE_UNFLAGGED",
                    severity=Severity.MEDIUM, tool_name=tool.name, evidence=verb,
                    message=f"Tool declares destructive_hint=false but its description "
                            f"implies a destructive action ('{verb}').",
                ))

            # No annotation at all on a side-effecting tool: can't gate it safely.
            if tool.read_only_hint is None and tool.destructive_hint is None:
                out.append(Finding(
                    detector_id=self.id, code="SCOPE.UNANNOTATED_SIDE_EFFECT",
                    severity=Severity.LOW, tool_name=tool.name, evidence=verb,
                    message=f"Side-effecting tool ('{verb}') carries no read_only / "
                            f"destructive annotation; a consent gate has nothing to key on.",
                ))
        return out
