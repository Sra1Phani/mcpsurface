# Contributing to mcpsurface

Thanks for looking. This is a small, deliberately narrow tool, and the bar
for changes is mostly about **evidence** rather than style.

## Sign your commits (DCO)

Every commit must carry a `Signed-off-by` line. Add it automatically:

```bash
git commit -s -m "your message"
```

which appends:

```
Signed-off-by: Your Name <your.email@example.com>
```

Use your real name and a working email. By signing off you certify the
Developer Certificate of Origin, reproduced in full at the bottom of this
file — in short, that you wrote the contribution or otherwise have the right
to submit it under this project's licence.

There is **no CLA**. You keep the copyright in your contribution; it is
licensed to the project under Apache-2.0 the same as everything else. If that
ever needs to change you will be asked first, in the open.

## Development

```bash
pip install -e ".[dev]"
pytest
```

Python ≥ 3.9, standard library only at runtime. `jsonschema` and `pytest` are
dev-only. **Do not add a runtime dependency** without discussing it first —
"installs and runs anywhere with no wheels to build" is a feature, and the
`--llm` path is the single sanctioned exception (opt-in, still unwired).

## The one rule that is unusual: calibrate against the corpus

This project once had a fully green test suite while mis-firing on **4.3% of
real servers**, because every fixture had been written by the same person who
wrote the patterns. The tests agreed with their own assumptions.

So: **if you change a detector pattern, measure it.**

```bash
python corpus/analyze.py corpus/data/*.jsonl
```

`corpus/` holds 13,474 real tool definitions from 598 servers, with
provenance. The number that matters is the **gate rate** — the share of a
(presumably benign) population that would exit 2 under the default
`--fail-on high`. It is currently **0.2%**. A pull request that raises it
needs to justify what it buys.

Two habits that follow from this:

- **A pattern that costs precision must buy a detection nothing else gets.**
  A real example: widening `before using any other tool` to `this tool`
  caught a known payload's phrasing but false-fired on ordinary usage
  guidance — and bought nothing, because that payload was already caught by
  another branch. It was reverted. The corpus is the arbiter, not intuition.
- **Pin real strings, not invented ones.** New regressions belong in
  `tests/test_corpus_calibration.py`, taken verbatim from the corpus. Every
  benign string added there should be fenced by an attack string the detector
  must still catch, so a precision fix cannot quietly hollow out recall.

If you add a corpus source, record provenance (where, which server, when) and
**declare what the source cannot see** — see below.

## Adding a detector

Subclass `Detector` in `src/mcpsurface/detectors/`, implement
`run(ctx) -> list[Finding]`, and add an instance to `REGISTRY` in
`detectors/__init__.py`. Nothing else needs changing — the runner, CLI and
JSON output pick it up. Set `requires_llm = True` to gate it behind `--llm`.

Detectors must not mutate `ScanContext`.

## House rules for this kind of tool

These exist because the project's entire value is not overclaiming. A scanner
that cries wolf, or that reports a guess as a fact, is worse than no scanner.

- **Never let a real distinction collapse into an absence.** "The server
  declares no annotations" and "this source strips annotations" are different
  facts. If a source cannot observe something, say so
  (`SCOPE.ANNOTATIONS_UNAVAILABLE`, `MANIFEST.NOT_CHECKED`) rather than
  reporting absence. Same for errors and skipped work — carry them as values,
  with reasons.
- **Never fake a pass.** An unverified signature reports
  `MANIFEST.SIG_UNVERIFIED`, never a green tick.
- **Normalize attacker-controlled text before matching words.** Run it through
  `text.normalize()` and write inter-word gaps as `\s+`, never a literal
  space — otherwise a second space, a newline, a zero-width character or a
  Cyrillic homoglyph walks a payload straight past your pattern. Conversely,
  character-level checks (hidden characters, mixed script) must read the
  **raw** text; normalizing is exactly what would erase their evidence.
- **Coerce at the parse boundary, not in detectors.** By the time a `Tool`
  exists its fields must already be the types they claim to be.
- **Know when to stop tuning a regex.** When a fix is reverse-engineered to
  pass one example and its regression lands in the common case, you have hit
  the precision/recall floor. Freeze precision-first, state the gap in the
  detector's docstring, and encode it as an `xfail(strict=True)` so closing it
  later cannot happen silently.

## Things that need discussion before a PR

- **The exit-code contract** (`0` clean, `2` finding at/above `--fail-on`,
  `1` operational error). CI consumers depend on the split.
- **`schema/report.schema.json`** and the shape of `to_json`. Adding a new
  finding *code* is fine — the schema does not enumerate them. Renaming an
  existing code is a breaking change.
- **Runtime dependencies**, and wiring a live `--llm` provider.

## Out of scope

mcpsurface is a **static audit**, not a gateway: no proxy, no runtime
enforcement, no auth brokering, no credential handling. It is also not a drift
monitor yet. Features in those directions are not rejected on principle, but
they change what the tool is, so open an issue first.

## Reporting a security issue

If you find a way to make a scan report *clean* when it should not — an
evasion — that is the highest-value bug this project can receive. Please open
an issue with a minimal tool definition that reproduces it. There is nothing
to disclose privately: this tool holds no credentials and guards no live
system, so evasions are discussed in the open where they can be fixed and
regression-tested.

---

## Developer Certificate of Origin

```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.


Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```
