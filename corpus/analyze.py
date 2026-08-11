#!/usr/bin/env python3
"""Run the detectors over the harvested corpus and measure the noise floor.

    python corpus/analyze.py corpus/data/*.jsonl [--samples 5] [--code INJ.EXFIL]

METHOD, and its one load-bearing assumption: the corpus is drawn from a public
registry's most-used servers, so the base rate of genuine tool poisoning in it
is very low. Under that assumption a HIGH/CRITICAL finding is a *candidate*
false positive — which is why this script prints samples rather than just a
rate. The rate tells you where to look; only reading the sample tells you
whether the detector was right. Do not quote a number from here without having
read the samples behind it.

The headline figure is the **gate rate**: the share of *sources* that would
exit 2 under the default `--fail-on high`. On a benign population that is, to
a first approximation, the share of users whose first run of this tool tells
them something alarming and wrong.

"Source", not "server", on purpose. A record here is one server when it comes
from the registry harvester and one *file* when it comes from the GitHub
harvester — several files can belong to one project. Calling the total a
server count overstates it, which is exactly the kind of rounding this tool
exists to catch other people doing.
"""
from __future__ import annotations

import argparse
import collections
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from corpus_io import load_records                     # noqa: E402
from mcpsurface.client import MCPClient          # noqa: E402
from mcpsurface.models import Severity           # noqa: E402
from mcpsurface.runner import scan               # noqa: E402

GATING = (Severity.HIGH, Severity.CRITICAL)


class _Corpus(MCPClient):
    def __init__(self, target: str, tools: list) -> None:
        super().__init__(target)
        self._tools = tools

    def _transport_list_tools(self):
        return self._tools

    def _transport_get_manifest(self):
        return None                              # corpus carries no manifests


def load(paths: list[str]) -> list[dict]:
    """All records, including errored ones; the summary reports them."""
    return load_records(paths, usable_only=False)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--samples", type=int, default=4)
    ap.add_argument("--code", help="show every hit for one code instead of a summary")
    args = ap.parse_args(argv)

    records = load(args.paths)
    usable = [r for r in records if not r.get("error") and r.get("tools")]

    n_tools = 0
    by_code: collections.Counter = collections.Counter()
    servers_by_code: collections.defaultdict = collections.defaultdict(set)
    tools_by_code: collections.defaultdict = collections.defaultdict(set)
    samples: collections.defaultdict = collections.defaultdict(list)
    gated: list[tuple] = []
    scan_errors: list[tuple] = []

    for rec in usable:
        qn = rec["qualified_name"]
        try:
            client = _Corpus(qn, rec["tools"])
            report = scan(qn, client.fetch_tools(), client.fetch_manifest())
        except Exception as e:                    # noqa: BLE001
            # A crash on real data is itself a finding — record, don't skip.
            scan_errors.append((qn, f"{type(e).__name__}: {e}"))
            continue

        n_tools += report.tools_scanned
        tool_text = {t["name"]: t for t in rec["tools"] if isinstance(t, dict)}
        worst = None
        for f in report.findings:
            if f.code == "MANIFEST.ABSENT":
                continue                          # corpus has no manifests by construction
            by_code[f.code] += 1
            servers_by_code[f.code].add(qn)
            tools_by_code[f.code].add((qn, f.tool_name))
            if len(samples[f.code]) < max(args.samples, 0) or args.code == f.code:
                raw = tool_text.get(f.tool_name or "", {})
                samples[f.code].append({
                    "server": qn, "tool": f.tool_name, "evidence": f.evidence,
                    "message": f.message,
                    "description": (raw.get("description") or "")[:400],
                })
            if f.severity in GATING:
                worst = f if worst is None or f.severity is Severity.CRITICAL else worst
        if worst is not None:
            gated.append((qn, worst.code, worst.tool_name, worst.evidence))

    if args.code:
        hits = samples.get(args.code, [])
        print(f"=== every sampled hit for {args.code} ({by_code[args.code]} total) ===\n")
        for h in hits:
            print(f"  {h['server']} :: {h['tool']}")
            print(f"    evidence: {h['evidence']!r}")
            print(f"    desc: {h['description']!r}\n")
        return 0

    print("=" * 72)
    print("CORPUS")
    print("=" * 72)
    print(f"  records            {len(records)}")
    print(f"  usable sources     {len(usable)}")   # servers OR source files
    print(f"  tool definitions   {n_tools}")
    if scan_errors:
        print(f"  SCAN CRASHES       {len(scan_errors)}  <-- detector bugs on real input")
        for qn, err in scan_errors[:5]:
            print(f"      {qn}: {err}")

    print()
    # A source that omits `annotations` makes every tool look unannotated,
    # which silently invalidates every scope_class rate below. Detect it and
    # say so, rather than printing a number that reads like a measurement.
    annotated = sum(
        1 for r in usable for t in r["tools"]
        if isinstance(t, dict) and isinstance(t.get("annotations"), dict) and t["annotations"]
    )
    if annotated == 0:
        print()
        print("!! NO TOOL IN THIS CORPUS CARRIES AN `annotations` BLOCK.")
        print("   The source strips the field, so scope_class rates below are")
        print("   ARTIFACTS, not measurements: READONLY_MISMATCH and")
        print("   DESTRUCTIVE_UNFLAGGED cannot fire, and UNANNOTATED_SIDE_EFFECT")
        print("   fires on everything write-shaped. Do not quote them.")

    print()
    print("=" * 72)
    print("FINDINGS BY CODE")
    print("=" * 72)
    print(f"  {'code':32} {'hits':>6} {'tools':>7} {'servers':>8}  {'%srv':>6}")
    for code, n in by_code.most_common():
        ns = len(servers_by_code[code])
        print(f"  {code:32} {n:>6} {len(tools_by_code[code]):>7} {ns:>8}  "
              f"{100.0*ns/len(usable):>5.1f}%")

    print()
    print("=" * 72)
    print("CI GATE IMPACT  (--fail-on high, the default)")
    print("=" * 72)
    ng = len({g[0] for g in gated})
    print(f"  sources that would exit 2:  {ng}/{len(usable)}  ({100.0*ng/len(usable):.1f}%)")
    print("  On a benign population this approximates the false-alarm rate of")
    print("  a first run. Each one below needs reading before it counts as a FP.")
    print()
    for qn, code, tool, ev in gated[:25]:
        print(f"    {code:26} {qn} :: {tool}")
        print(f"      {ev!r}")
    if len(gated) > 25:
        print(f"    … and {len(gated)-25} more")

    print()
    print("=" * 72)
    print("SAMPLES  (read these; the rate alone proves nothing)")
    print("=" * 72)
    for code in by_code:
        print(f"\n--- {code}")
        for h in samples[code][:args.samples]:
            print(f"  {h['server']} :: {h['tool']}")
            print(f"    evidence: {h['evidence']!r}")
            d = h["description"].replace("\n", " ")
            print(f"    desc:     {d[:200]!r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
