#!/usr/bin/env python3
"""Compare two dated corpus snapshots and report what changed.

    python corpus/diff_snapshots.py OLD.jsonl[.gz] NEW.jsonl[.gz]

This is what the archive is *for*. A single snapshot of a public registry is
cheap to reproduce; a dated series is not, because you cannot go back and
harvest last month. What the series buys you is the question no single scan
can answer: **did this server's advertised surface change, and did the change
make it worse?**

Note what this does not need. Detecting drift here requires no MCP transport,
no manifest, and no trust anchor from the server, because the comparison is
between two observations you made yourself. A server cannot lie about what it
told you last week.

Findings are ordered by how much they should worry you:

  1. REGRESSIONS  a description changed, and the new text trips a detector
                  that the old text did not. This is the rug-pull shape.
  2. SURFACE      tools appeared or disappeared on an existing server.
  3. EDITS        descriptions changed without tripping anything.
  4. ROSTER       servers entering or leaving the corpus.

A regression is the only category that is alarming on its own. The rest is
ordinary software changing, and is reported so that a human can notice a
pattern, not so a CI job can fail on it.
"""
from __future__ import annotations

import argparse
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from corpus_io import load_records                 # noqa: E402
from mcpsurface.client import MCPClient            # noqa: E402
from mcpsurface.models import Severity             # noqa: E402
from mcpsurface.runner import scan                 # noqa: E402

GATING = (Severity.HIGH, Severity.CRITICAL)


class _One(MCPClient):
    def __init__(self, tool):
        super().__init__("diff")
        self._tool = tool

    def _transport_list_tools(self):
        return [self._tool]

    def _transport_get_manifest(self):
        return None


def gating_codes(tool: dict) -> set:
    """Codes at or above HIGH that this single tool definition trips."""
    try:
        c = _One(tool)
        rep = scan("diff", c.fetch_tools(), c.fetch_manifest())
    except Exception:                                # noqa: BLE001
        return set()
    return {f.code for f in rep.findings if f.severity in GATING}


def index(records: list[dict]) -> dict:
    """qualified_name -> {tool name -> tool dict}."""
    out = {}
    for r in records:
        tools = {t.get("name", ""): t for t in r.get("tools") or []
                 if isinstance(t, dict)}
        out[r["qualified_name"]] = tools
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("old")
    ap.add_argument("new")
    ap.add_argument("--show", type=int, default=10, help="max examples per section")
    args = ap.parse_args(argv)

    old = index(load_records([args.old]))
    new = index(load_records([args.new]))

    added_srv = sorted(set(new) - set(old))
    removed_srv = sorted(set(old) - set(new))
    common = sorted(set(old) & set(new))

    regressions, surface, edits = [], [], []

    for qn in common:
        o, n = old[qn], new[qn]
        gained = sorted(set(n) - set(o))
        lost = sorted(set(o) - set(n))
        if gained or lost:
            surface.append((qn, gained, lost))
        for name in sorted(set(o) & set(n)):
            od = (o[name].get("description") or "")
            nd = (n[name].get("description") or "")
            if od == nd:
                continue
            before, after = gating_codes(o[name]), gating_codes(n[name])
            introduced = after - before
            if introduced:
                regressions.append((qn, name, sorted(introduced), od, nd))
            else:
                edits.append((qn, name, od, nd))

    print(f"old: {args.old}   ({len(old)} sources)")
    print(f"new: {args.new}   ({len(new)} sources)")
    print()

    print("=" * 72)
    print(f"1. REGRESSIONS — description changed AND now trips a detector: {len(regressions)}")
    print("=" * 72)
    if not regressions:
        print("  none")
    for qn, name, codes, od, nd in regressions[:args.show]:
        print(f"\n  !! {qn} :: {name}   {codes}")
        print(f"     was: {od[:160]!r}")
        print(f"     now: {nd[:160]!r}")

    print()
    print("=" * 72)
    print(f"2. SURFACE — tools added or removed on an existing server: {len(surface)}")
    print("=" * 72)
    for qn, gained, lost in surface[:args.show]:
        bits = []
        if gained:
            bits.append(f"+{len(gained)} {gained[:4]}")
        if lost:
            bits.append(f"-{len(lost)} {lost[:4]}")
        print(f"  {qn}: {'  '.join(bits)}")
    if len(surface) > args.show:
        print(f"  … and {len(surface) - args.show} more")

    print()
    print("=" * 72)
    print(f"3. EDITS — descriptions reworded, nothing tripped: {len(edits)}")
    print("=" * 72)
    for qn, name, od, nd in edits[:args.show]:
        print(f"  {qn} :: {name}")
    if len(edits) > args.show:
        print(f"  … and {len(edits) - args.show} more")

    print()
    print("=" * 72)
    print(f"4. ROSTER — servers added: {len(added_srv)}, removed: {len(removed_srv)}")
    print("=" * 72)
    print(f"  added:   {added_srv[:args.show]}")
    print(f"  removed: {removed_srv[:args.show]}")

    # Exit 2 only for regressions, matching the scanner's own contract: a
    # finding worth gating on. Ordinary churn is not a failure.
    return 2 if regressions else 0


if __name__ == "__main__":
    raise SystemExit(main())
