"""Shared corpus reading, so every tool accepts the same inputs.

Archived snapshots are gzipped (JSONL of this shape compresses about 5:1), so
a loader that only understands plain `.jsonl` would make the archive unusable
by the tools it exists to feed. Both forms are read transparently, chosen by
extension, using stdlib gzip so nothing here adds a dependency.
"""
from __future__ import annotations

import gzip
import io
import json
import sys


def open_text(path: str) -> io.TextIOBase:
    """Open .jsonl or .jsonl.gz as text."""
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8")
    return open(path, encoding="utf-8")


def load_records(paths: list[str], usable_only: bool = True) -> list[dict]:
    """Read corpus JSONL(.gz).

    `usable_only` drops records that errored or carry no tools, which is what
    every measurement wants. Pass False when you care about the failures
    themselves — a harvest where half the fetches errored is a fact about the
    harvest, and silently discarding it would flatter whatever you measure.

    A missing file is the expected first-run state, since the corpus is not
    committed. That gets a message rather than a traceback.
    """
    out: list[dict] = []
    missing: list[str] = []
    for p in paths:
        try:
            with open_text(p) as fh:
                for line in fh:
                    if not line.strip():
                        continue
                    r = json.loads(line)
                    if usable_only and (r.get("error") or not r.get("tools")):
                        continue
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
