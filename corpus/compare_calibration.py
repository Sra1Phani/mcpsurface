#!/usr/bin/env python3
"""Measure the gate rate before and after calibration, on the same corpus.

    python corpus/compare_calibration.py corpus/data/smithery-registry-*.jsonl

The "before" side uses `precalibration.py`, which is a **reconstruction** of
the pre-calibration patterns rebuilt from the documented changes — the
originals predate this repository and no longer exist. Read that module's
docstring before quoting anything from here.

The point of this script is that the published 4.3% should be checkable
rather than taken on trust. If it disagrees, that is a finding about the
published number, not a bug to tune away.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import precalibration                                    # noqa: E402
from mcpsurface.client import MCPClient                  # noqa: E402
from mcpsurface.models import Severity                   # noqa: E402
from mcpsurface.runner import scan                       # noqa: E402

GATING = (Severity.HIGH, Severity.CRITICAL)


class _Corpus(MCPClient):
    def __init__(self, target, tools):
        super().__init__(target)
        self._tools = tools

    def _transport_list_tools(self):
        return self._tools

    def _transport_get_manifest(self):
        return None


def load(paths):
    """Read corpus JSONL. A missing file is the expected first-run state.

    `corpus/data/` is deliberately not committed, so anyone following the
    write-up reaches this script before they have harvested anything. A
    traceback here would be exactly the alarming-and-wrong first run this
    project exists to argue against.
    """
    out, missing = [], []
    for p in paths:
        try:
            with open(p, encoding="utf-8") as fh:
                for line in fh:
                    if line.strip():
                        r = json.loads(line)
                        if not r.get("error") and r.get("tools"):
                            out.append(r)
        except FileNotFoundError:
            missing.append(p)
    if missing and not out:
        raise SystemExit(
            "no corpus found: " + ", ".join(missing) + "\n\n"
            "The corpus is not committed (it is ~10MB of third-party tool\n"
            "descriptions). Build it first, which takes a couple of minutes:\n\n"
            "    python corpus/harvest.py --servers 500\n\n"
            "then re-run this against corpus/data/*.jsonl"
        )
    for p in missing:
        print(f"  warning: skipped missing file {p}", file=sys.stderr)
    return out


def measure(records):
    """Sources with at least one HIGH/CRITICAL finding, and which codes fired."""
    gated, codes, errors = set(), {}, 0
    for r in records:
        c = _Corpus(r["qualified_name"], r["tools"])
        try:
            rep = scan(r["qualified_name"], c.fetch_tools(), c.fetch_manifest())
        except Exception:                                 # noqa: BLE001
            errors += 1
            continue
        for f in rep.findings:
            if f.severity in GATING:
                gated.add(r["qualified_name"])
                codes[f.code] = codes.get(f.code, 0) + 1
    return gated, codes, errors


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("paths", nargs="+")
    args = ap.parse_args(argv)

    records = load(args.paths)
    n = len(records)
    print(f"corpus: {n} usable sources, "
          f"{sum(len(r['tools']) for r in records)} tool definitions\n")

    saved = precalibration.apply()
    try:
        before, before_codes, before_err = measure(records)
    finally:
        precalibration.restore(saved)
    after, after_codes, after_err = measure(records)

    def pct(k):
        return f"{100.0 * k / n:.1f}%" if n else "n/a"

    print(f"  BEFORE (reconstructed)  {len(before):>4}/{n}  {pct(len(before)):>6}"
          f"   {dict(sorted(before_codes.items()))}")
    print(f"  AFTER  (as shipped)     {len(after):>4}/{n}  {pct(len(after)):>6}"
          f"   {dict(sorted(after_codes.items()))}")
    if before_err or after_err:
        print(f"  scan errors: before={before_err} after={after_err}")

    print()
    print("  NOTE: the BEFORE side is a reconstruction of patterns that predate")
    print("  this repository. It is the best available check on the published")
    print("  figure, not the original measurement.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
