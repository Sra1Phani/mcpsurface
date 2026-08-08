"""mcpsurface CLI.

    mcpsurface <server-url> [--json] [--llm] [--fail-on SEV]

--json       emit the machine report (what a CI Action consumes)
--llm        enable the opt-in LLM judge (needs a provider wired in)
--fail-on    exit non-zero if any finding >= SEV (default: high) -> CI gate

Exit codes make this drop into CI later with zero glue: 0 clean/under
threshold, 2 threshold breached, 1 operational error.
"""
from __future__ import annotations

import argparse
import sys

from . import report as report_mod
from .client import MCPClient
from .models import Severity
from .runner import scan

_SEV_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]

#: The LLM judge callable, or None when no provider is wired into this build.
#: Wiring one is gated on human approval (it introduces a network + key
#: dependency); see CONTRIBUTING.md. Keep this the single place that knows, so
#: `--llm` can tell the user the truth instead of silently doing nothing.
LLM_JUDGE = None


def _breaches(report, threshold: Severity) -> bool:
    ti = _SEV_ORDER.index(threshold)
    return any(_SEV_ORDER.index(f.severity) >= ti for f in report.findings)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="mcpsurface",
        description="Trust scan for an MCP server (static audit, not a gateway).",
        epilog="targets:  smithery:<name>  scan a registry-indexed server "
               "(works today, e.g. smithery:exa)  |  <url>  scan a server "
               "directly (MCP transport not wired yet)",
    )
    p.add_argument("target",
                   help="smithery:<qualified-name>, or an MCP server URL")
    p.add_argument("--json", action="store_true", help="emit JSON report")
    p.add_argument("--llm", action="store_true", help="enable opt-in LLM judge")
    p.add_argument("--fail-on", default="high",
                   choices=[s.value for s in Severity],
                   help="exit non-zero if a finding at/above this severity exists")
    args = p.parse_args(argv)

    # A flag that quietly does nothing is worse than one that isn't offered:
    # the user reads an unchanged report as "the judge found nothing".
    if args.llm and LLM_JUDGE is None:
        print("warning: --llm has no effect — no LLM judge provider is wired into "
              "this build, so only the offline heuristics ran.", file=sys.stderr)

    # Everything that touches server-controlled data is inside the guard.
    # `scan()` used to sit outside it, so a malformed payload escaped as a
    # traceback rather than the documented exit-1 operational error.
    try:
        client = MCPClient.for_target(args.target)
        tools = client.fetch_tools()
        manifest = client.fetch_manifest()
        rep = scan(args.target, tools, manifest, use_llm=args.llm, llm=LLM_JUDGE,
                   annotations_available=client.supports_annotations,
                   manifest_available=client.supports_manifest)
        rendered = report_mod.to_json(rep) if args.json else report_mod.to_table(rep)
    except NotImplementedError as e:
        print(f"transport not wired: {e}\n"
              f"hint: direct URL scanning needs the MCP transport, which is not "
              f"implemented yet. To scan a registry-indexed server today, use "
              f"'mcpsurface smithery:<name>' (e.g. smithery:exa).", file=sys.stderr)
        return 1
    except Exception as e:  # noqa: BLE001 - top-level guard
        print(f"error: {e}", file=sys.stderr)
        return 1

    print(rendered)
    return 2 if _breaches(rep, Severity(args.fail_on)) else 0


if __name__ == "__main__":
    raise SystemExit(main())
