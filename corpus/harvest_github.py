#!/usr/bin/env python3
"""Harvest tool definitions that CARRY ANNOTATIONS, from server source on GitHub.

Why a second harvester: the Smithery registry strips the `annotations` field
(verified — 12,696 tool objects, not one had it), so that corpus cannot
calibrate `scope_class` at all. Its two contradiction codes can never fire
there, and UNANNOTATED_SIDE_EFFECT fires on everything. This source keeps the
annotations, because it reads what the author actually wrote.

    python corpus/harvest_github.py --files 300 --out corpus/data

Method: GitHub code search for `readOnlyHint` (tens of thousands of real hits),
fetch each matching file at its pinned commit, and extract every tool
definition that declares annotations. Provenance is the repo, path, commit sha
and permalink, so any record can be re-read at the exact revision measured.

Parsing is deliberately conservative — it would rather skip a definition than
invent one. TypeScript is brace-matched with a real string/comment-aware
scanner (naive matching breaks on `{` inside a description). Python uses `ast`.
Anything not confidently parsed is counted in `skipped`, never silently
dropped: a corpus that quietly loses the hard cases would flatter whatever it
measures.

Requires `gh` to be authenticated (code search needs a token).
"""
from __future__ import annotations

import argparse
import ast
import json
import pathlib
import re
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone

SOURCE_ID = "github-source"
UA = {"User-Agent": "mcpsurface-corpus/0.1"}

# --- TypeScript: string/comment-aware brace scanner --------------------------


def _scan_ts(src: str):
    """Yield (depth, open_idx, close_idx) for every object literal.

    Tracks '…', "…", `…` and // /* comments so braces inside them don't count.
    """
    pairs, stack = [], []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if c in "\"'`":
            q, i = c, i + 1
            while i < n:
                if src[i] == "\\":
                    i += 2
                    continue
                if src[i] == q:
                    break
                i += 1
        elif c == "/" and i + 1 < n and src[i + 1] == "/":
            i = src.find("\n", i)
            if i == -1:
                break
        elif c == "/" and i + 1 < n and src[i + 1] == "*":
            j = src.find("*/", i + 2)
            i = n if j == -1 else j + 1
        elif c == "{":
            stack.append(i)
        elif c == "}":
            if stack:
                o = stack.pop()
                pairs.append((len(stack), o, i))
        i += 1
    return pairs


_STR = r"""(?:"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)'|`((?:[^`\\]|\\.)*)`)"""


def _unescape(s: str) -> str:
    try:
        return json.loads('"' + s.replace('"', '\\"').replace("\\'", "'") + '"')
    except Exception:                                    # noqa: BLE001
        return s.replace("\\n", "\n").replace("\\t", "\t").replace('\\"', '"')


def _ts_key(body: str, key: str) -> str | None:
    """Value of a top-level string key inside one object body."""
    depth = 0
    for d, o, c in _scan_ts(body):
        pass
    m = re.search(rf"(?<![\w.]){key}\s*:\s*{_STR}", body)
    if not m:
        return None
    raw = next((g for g in m.groups() if g is not None), None)
    return _unescape(raw) if raw is not None else None


_BOOL_HINT = re.compile(
    r"(readOnlyHint|destructiveHint|idempotentHint|openWorldHint)\s*:\s*(true|false)",
    re.IGNORECASE,
)


def extract_typescript(src: str) -> tuple[list[dict], int]:
    """Every object literal that declares MCP annotations, as tool dicts."""
    out, skipped = [], 0
    pairs = _scan_ts(src)
    # innermost-first so the annotations block resolves to its own tool object
    for depth, o, c in sorted(pairs, key=lambda p: -p[0]):
        body = src[o + 1:c]
        if not re.search(r"(?<![\w.])annotations\s*:", body):
            continue
        am = re.search(r"(?<![\w.])annotations\s*:\s*\{", body)
        if not am:
            continue
        astart = o + 1 + am.end() - 1
        ablock = next((src[ao:ac + 1] for d2, ao, ac in pairs if ao == astart), "")
        hints = {k.lower(): v.lower() == "true" for k, v in _BOOL_HINT.findall(ablock)}
        if not hints:
            continue

        name = _ts_key(body, "name")
        desc = _ts_key(body, "description")
        if not name:
            # registerTool("name", { … }) / tool("name", { … }) — name is positional
            pre = src[max(0, o - 200):o]
            pm = re.findall(rf"(?:registerTool|tool|addTool)\s*\(\s*{_STR}", pre)
            if pm:
                g = pm[-1]
                name = _unescape(next((x for x in g if x), ""))
        if not (name and desc):
            skipped += 1
            continue
        out.append({
            "name": name, "description": desc,
            "annotations": {
                "readOnlyHint": hints.get("readonlyhint"),
                "destructiveHint": hints.get("destructivehint"),
                "idempotentHint": hints.get("idempotenthint"),
                "openWorldHint": hints.get("openworldhint"),
            },
        })
    # de-dup identical (name, description) pairs produced by nested matches
    seen, uniq = set(), []
    for t in out:
        k = (t["name"], t["description"])
        if k not in seen:
            seen.add(k)
            uniq.append(t)
    return uniq, skipped


# --- Python: real AST ---------------------------------------------------------


def _py_const(node):
    return node.value if isinstance(node, ast.Constant) else None


def extract_python(src: str) -> tuple[list[dict], int]:
    out, skipped = [], 0
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return [], 1
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        fname = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
        if fname not in ("Tool", "ToolDefinition"):
            continue
        kw = {k.arg: k.value for k in node.keywords if k.arg}
        if "annotations" not in kw:
            continue
        hints: dict = {}
        av = kw["annotations"]
        if isinstance(av, ast.Call):
            for k in av.keywords:
                if k.arg and isinstance(_py_const(k.value), bool):
                    hints[k.arg] = _py_const(k.value)
        elif isinstance(av, ast.Dict):
            for k, v in zip(av.keys, av.values):
                key = _py_const(k)
                if isinstance(key, str) and isinstance(_py_const(v), bool):
                    hints[key] = _py_const(v)
        name, desc = _py_const(kw.get("name")), _py_const(kw.get("description"))
        if not (isinstance(name, str) and isinstance(desc, str) and hints):
            skipped += 1
            continue
        out.append({"name": name, "description": desc, "annotations": {
            "readOnlyHint": hints.get("readOnlyHint"),
            "destructiveHint": hints.get("destructiveHint"),
            "idempotentHint": hints.get("idempotentHint"),
            "openWorldHint": hints.get("openWorldHint"),
        }})
    return out, skipped


# --- fetching -----------------------------------------------------------------


def code_search(query: str, pages: int) -> list[dict]:
    items = []
    for page in range(1, pages + 1):
        try:
            raw = subprocess.run(
                ["gh", "api", f"search/code?q={query}&per_page=100&page={page}"],
                capture_output=True, text=True, timeout=60,
            )
            if raw.returncode != 0:
                print(f"  search page {page} failed: {raw.stderr[:120]}", file=sys.stderr)
                break
            batch = json.loads(raw.stdout).get("items", [])
        except Exception as e:                            # noqa: BLE001
            print(f"  search page {page} error: {e}", file=sys.stderr)
            break
        if not batch:
            break
        items.extend(batch)
        time.sleep(6)          # code search is ~10 req/min authenticated
    return items


def raw_url(item: dict) -> str | None:
    m = re.match(r"https://github\.com/([^/]+/[^/]+)/blob/([0-9a-f]{7,40})/(.+)",
                 item.get("html_url", ""))
    if not m:
        return None
    repo, sha, path = m.groups()
    return f"https://raw.githubusercontent.com/{repo}/{sha}/{path}"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--files", type=int, default=300)
    ap.add_argument("--out", default="corpus/data")
    args = ap.parse_args(argv)

    queries = [
        "readOnlyHint+language:typescript",
        "destructiveHint+language:typescript",
        "readOnlyHint+language:python",
    ]
    items, seen = [], set()
    per = max(1, args.files // len(queries) // 100 + 1)
    for q in queries:
        print(f"searching {q} …", file=sys.stderr)
        for it in code_search(q, per):
            key = it.get("html_url")
            if key and key not in seen:
                seen.add(key)
                items.append(it)
    items = items[:args.files]
    print(f"  {len(items)} unique files", file=sys.stderr)

    records, tot, skipped_tot = [], 0, 0
    for i, it in enumerate(items, 1):
        url = raw_url(it)
        if not url:
            continue
        try:
            req = urllib.request.Request(url, headers=UA)
            with urllib.request.urlopen(req, timeout=25) as r:
                src = r.read().decode("utf-8", "replace")
        except Exception as e:                            # noqa: BLE001
            records.append({"source": SOURCE_ID, "source_url": url,
                            "repo": it["repository"]["full_name"],
                            "path": it.get("path"), "tools": [],
                            "fetched_at": datetime.now(timezone.utc).isoformat(),
                            "error": f"{type(e).__name__}: {e}"[:150]})
            continue
        if it.get("path", "").endswith(".py"):
            tools, sk = extract_python(src)
        else:
            tools, sk = extract_typescript(src)
        tot += len(tools)
        skipped_tot += sk
        records.append({
            "source": SOURCE_ID, "source_url": url,
            "repo": it["repository"]["full_name"], "path": it.get("path"),
            "qualified_name": f"{it['repository']['full_name']}:{it.get('path')}",
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            "tools": tools, "skipped_unparsed": sk, "error": None,
        })
        if i % 50 == 0:
            print(f"  {i}/{len(items)} files, {tot} annotated tools", file=sys.stderr)

    outdir = pathlib.Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    path = outdir / f"{SOURCE_ID}-{stamp}.jsonl"
    with path.open("w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    print(f"\nwrote {path}", file=sys.stderr)
    print(f"  files {len(records)}  annotated tools {tot}  unparsed {skipped_tot}",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
