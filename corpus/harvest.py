#!/usr/bin/env python3
"""Harvest real MCP tool definitions into a provenance-tagged corpus.

Why this exists: every input the detectors had ever seen was written by us,
imagining what an attack looks like. A green test suite measured agreement
with our own assumptions, not fitness against reality. This pulls real
`tools/list` payloads from deployed servers so the false-positive rate can be
measured instead of guessed.

Source: the Smithery registry, which returns each server's actual advertised
tool list — name, description and inputSchema — rather than metadata about it.
That means no source-code parsing and no guessing at what a server advertises.

    python corpus/harvest.py --servers 200 --out corpus/data

Stdlib only, matching the package's no-runtime-deps rule. Output is JSONL,
one record per server, each carrying enough provenance to re-fetch and date it:
the corpus is meant to accumulate, so records must stay attributable.

CORPUS BIAS — read before drawing conclusions. Smithery indexes *hosted,
remotely-deployed* servers. Local stdio servers (npx/uvx packages wired into a
desktop config) are under-represented, and they may skew toward different
authors and conventions. Ordering is the registry's default, which tracks
popularity, so this is weighted toward servers people actually use — good for
a noise-floor estimate, not a uniform sample of the ecosystem.

!! THIS SOURCE STRIPS `annotations`. Verified 2026-08-08: across 12,696 tool
objects the only keys present are name / description / inputSchema /
outputSchema. Not one carried an `annotations` block, while GitHub code search
returns tens of thousands of real `readOnlyHint` uses — so the absence is an
artifact of this API, not a fact about the ecosystem.

CONSEQUENCE: this corpus CANNOT calibrate the `scope_class` detector. Every
tool looks unannotated, so SCOPE.READONLY_MISMATCH and
SCOPE.DESTRUCTIVE_UNFLAGGED can never fire and SCOPE.UNANNOTATED_SIDE_EFFECT
fires on everything write-shaped. Any scope_class rate measured here is
meaningless. Calibrating that detector needs a source that preserves
annotations — extract from server source on GitHub, or call `tools/list`
directly once the transport is wired. The injection detectors are unaffected:
they read descriptions, which this source returns intact.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

REGISTRY = "https://registry.smithery.ai"
USER_AGENT = "mcp-trust-scanner-corpus/0.1 (+calibration research)"
SOURCE_ID = "smithery-registry"


def _get(url: str, timeout: int = 20, retries: int = 3) -> dict:
    last: Exception | None = None
    for attempt in range(retries):
        req = urllib.request.Request(url, headers={
            "Accept": "application/json", "User-Agent": USER_AGENT,
        })
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read().decode("utf-8"))
        except Exception as e:                      # noqa: BLE001
            last = e
            time.sleep(1.5 * (attempt + 1))         # be polite; back off
    raise RuntimeError(f"GET {url} failed after {retries} tries: {last}")


def list_servers(target: int, page_size: int = 100) -> list[dict]:
    """Registry listing, in default (popularity-ish) order."""
    out: list[dict] = []
    page = 1
    while len(out) < target:
        data = _get(f"{REGISTRY}/servers?page={page}&pageSize={page_size}")
        batch = data.get("servers") or []
        if not batch:
            break
        out.extend(batch)
        pag = data.get("pagination") or {}
        if page >= int(pag.get("totalPages") or 0):
            break
        page += 1
        time.sleep(0.2)
    return out[:target]


def fetch_tools(entry: dict) -> dict:
    """Fetch one server's advertised tools, with provenance.

    A fetch that fails is recorded as a record with an `error`, never dropped:
    "we could not read this server" and "this server has no tools" are
    different facts about the corpus and must not look the same downstream.
    """
    qn = entry.get("qualifiedName") or ""
    record = {
        "source": SOURCE_ID,
        "source_url": f"{REGISTRY}/servers/{urllib.parse.quote(qn, safe='@/')}",
        "qualified_name": qn,
        "display_name": entry.get("displayName"),
        "namespace": entry.get("namespace"),
        "owner": entry.get("owner"),
        "homepage": entry.get("homepage"),
        "use_count": entry.get("useCount"),
        "verified": entry.get("verified"),
        "by_smithery": entry.get("bySmithery"),
        "is_deployed": entry.get("isDeployed"),
        "remote": entry.get("remote"),
        "registry_created_at": entry.get("createdAt"),
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "tools": [],
        "error": None,
    }
    try:
        detail = _get(record["source_url"])
        if "error" in detail and "tools" not in detail:
            record["error"] = str(detail.get("error"))[:200]
        else:
            tools = detail.get("tools")
            record["tools"] = tools if isinstance(tools, list) else []
            record["server_description"] = detail.get("description")
    except Exception as e:                          # noqa: BLE001
        record["error"] = f"{type(e).__name__}: {e}"[:200]
    return record


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--servers", type=int, default=200, help="how many to fetch")
    p.add_argument("--workers", type=int, default=6, help="concurrent fetches")
    p.add_argument("--out", default="corpus/data", help="output directory")
    args = p.parse_args(argv)

    print(f"listing {args.servers} servers from {REGISTRY} …", file=sys.stderr)
    entries = list_servers(args.servers)
    print(f"  got {len(entries)}", file=sys.stderr)

    records: list[dict] = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        for i, rec in enumerate(pool.map(fetch_tools, entries), 1):
            records.append(rec)
            if i % 25 == 0:
                print(f"  fetched {i}/{len(entries)}", file=sys.stderr)

    outdir = pathlib.Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    path = outdir / f"{SOURCE_ID}-{stamp}.jsonl"
    with path.open("w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")

    ok = [r for r in records if not r["error"]]
    tools = sum(len(r["tools"]) for r in ok)
    errs = len(records) - len(ok)
    print(f"\nwrote {path}", file=sys.stderr)
    print(f"  servers: {len(records)}  readable: {len(ok)}  errored: {errs}", file=sys.stderr)
    print(f"  with >=1 tool: {sum(1 for r in ok if r['tools'])}", file=sys.stderr)
    print(f"  tool definitions: {tools}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
