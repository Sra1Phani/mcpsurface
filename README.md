# mcpsurface

Point it at an MCP server, get back a trust report on the things the
gateways skip: **tool-description poisoning, manifest integrity, and
capability drift.**

```bash
mcpsurface smithery:exa                    # scan a registry-indexed server
mcpsurface smithery:gmail --json           # machine report
mcpsurface smithery:exa --fail-on high     # CI gate (exit 2 on a finding)
```

> ### Status: v0 — an **onboarding check**, not a drift monitor
>
> **What works today:** scanning any of the ~7,600 servers indexed by the
> Smithery registry, via `smithery:<name>`. Detection, the report contract,
> and the CI exit-code gate are all live.
>
> **What doesn't:** `mcpsurface <url>` against a server directly. The MCP
> transport is still a stub and exits 1 — see [Status](#status).
>
> **What this means:** the registry is a *second-hand* source. You are
> scanning what the registry recorded, not what the server would answer
> your agent. That is enough to vet a server **before** you onboard it. It
> is not enough to detect a server that serves clean descriptions to an
> indexer and poisoned ones to a live client, and it does not watch for
> changes after you look. Both need the transport.

## Why this exists

MCP gateways (Kong, Composio, MintMCP, Lasso, …) govern *your* agents
talking to a *curated registry of approved* servers inside your
perimeter. They assume trust is already established. This tool checks the
thing they assume: **is this specific server's tool surface actually safe
to connect to?** It rides the gap several gateways explicitly leave open —
rug-pull, tool poisoning, cross-server shadowing.

## What it checks (v0)

| Detector | Catches | |
|---|---|---|
| `injection` | Instructions aimed at the agent, exfiltration phrasing, secrecy directives, hidden zero-width / bidi characters, homoglyph substitution | ✅ |
| `scope_class` | Tools whose described behavior (delete, transfer, pay…) contradicts their declared MCP annotations (`readOnlyHint`, `destructiveHint`) | ✅ |
| `manifest` | `.well-known/mcp.json` presence, **expiry** (missing, unparseable, or elapsed), same-origin vs cross-origin, and **capability-digest diff** (declared tool set vs. live — silent expansion / rug-pull) | ✅ |
| `llm_judge` | Subtler poisoning the heuristics miss — multi-clause and pronoun-referenced exfiltration in particular | ❌ **not implemented.** No such detector exists yet; `--llm` is accepted and warns that it had no effect |

`injection` scans every string the agent reads into its context — the tool
description, the tool **name**, and every `description` / `title` in the
**input schema**. Parameter descriptions matter here: they are a documented
poisoning vector precisely because they're less visible to human review.

The core is **heuristic, deterministic, and dependency-free** — no model
provider, no API key, no account, so it runs in CI on every PR and gives
the same answer every time. (It is not *offline*: fetching a server's tool
surface is a network call. What it never calls is a model.) `--llm` is an
optional upgrade once a provider is wired in.

### Calibrated against real servers, not fixtures

The detectors are tuned against a corpus of **13,474 real tool definitions
from 598 servers** (`corpus/`, with provenance and a re-runnable harvester).
That took the false-alarm rate on a CI gate from 4.3% of servers to **0.2%**
while *increasing* the number of documented attack shapes caught. Corpus
strings are pinned as regression tests in `tests/test_corpus_calibration.py`
— real strings outrank invented ones.

Worth knowing before you trust a clean result: that same corpus contained
**zero actual attacks**. A clean scan is consistent with a clean ecosystem,
not proof your server is safe.

## What it does NOT do (read this)

- **Not a gateway.** No proxy, no runtime enforcement, no auth brokering. Static audit only.
- **Not a drift monitor.** It answers "is this safe to onboard?", once. It does not watch a server for changes afterwards, and a CI run fires on *your* commits, not on the server operator's edits — the two are uncorrelated. Rug-pull detection needs the transport plus a committed baseline; neither exists yet.
- **Second-hand data on the `smithery:` path.** You see the registry's index, not the live server. It cannot catch a server that shows one face to an indexer and another to your agent.
- **Cannot check annotations or manifests on the `smithery:` path.** The registry supplies neither. The report says so explicitly (`SCOPE.ANNOTATIONS_UNAVAILABLE`, `MANIFEST.NOT_CHECKED`) rather than reporting them as absent — "not observable from here" is not the same as "the server declares nothing".
- **Does not scan a server by URL yet.** The MCP transport is a stub; see [Status](#status).
- **Does not verify cross-origin attestation** (shop ≠ platform). v0 only *flags* that cross-origin is in play; the attestation handshake is a separate, harder spec.
- **Signature verification is stubbed.** Manifests are treated as unauthenticated until DNS-key verification lands. Until it does, **manifest integrity has no independent trust anchor**: the manifest and the tool list come from the same server, so `capabilities_digest` proves self-consistency, not honesty. A server that lies about both passes. That's why `MANIFEST.DIGEST_MISMATCH` is LOW and never gates.
- **No cross-server checks.** Tool shadowing between servers is out of scope — a scan sees one server's surface and has no representation of any other's.
- **Heuristics are not exhaustive.** A clean scan is not a safety guarantee — it's the absence of *known shapes*. `INJ.EXFIL` in particular is precision-first by design and misses the dominant multi-clause exfil grammar; see `InjectionDetector`'s docstring.
- **A static scan is point-in-time.** A server can serve clean tool descriptions to a scanner and poisoned ones to an agent. Re-scanning narrows that window; it doesn't close it.

A passing scan means "no known poisoning patterns and no declared/actual
contradiction." It does **not** mean the server is trustworthy. Trust
still needs the consent gate and untrusted-data discipline on the agent
side; this tool narrows the surface, it doesn't close it.

## Adding a detector

Subclass `Detector`, implement `run(ctx) -> list[Finding]`, register it in
`detectors/__init__.py`. That's the only wiring. The runner, CLI, and JSON
output pick it up automatically.

## Status

v0 skeleton. Two stubs stand between this and a live scan:

| Stub | Where | What wiring it takes |
|---|---|---|
| MCP transport | `client.py` `_transport_list_tools` / `_transport_get_manifest` | A `tools/list` call and a `.well-known/mcp.json` fetch — plus, because the target is hostile by assumption, a request timeout, a response-size cap, and SSRF-safe redirect handling that resolves the *final* host before connecting (see the `TODO(security)` block in the file) |
| DNS-key signature verify | `detectors/manifest.py` | A DNS resolver and ed25519 verification. Note this breaks "dependency-free" — and it is the only thing that would give manifest integrity a trust anchor the scanned server doesn't control |

Neither fakes a pass: an unverified signature reports
`MANIFEST.SIG_UNVERIFIED` (LOW, "treat as unauthenticated"), never a
green tick. The detection logic and report contract are complete and
tested — see `tests/` for end-to-end runs against fixture servers.

## Exit codes

`0` clean / under threshold · `2` finding at/above `--fail-on` · `1` error.
Designed so a GitHub Action drops in with no glue — parse the `--json`
output (see `src/mcpsurface/schema/report.schema.json`).

## License

Apache-2.0.
