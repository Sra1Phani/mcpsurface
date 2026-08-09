# mcpsurface (npm launcher)

> **This package is a launcher, not the scanner.** It requires **Python 3.9+**
> and the `mcpsurface` Python package. If you want a pure-JavaScript tool, this
> is not it — and better to know now than after installing.

Audit what an MCP server advertises to your agent: tool descriptions that read
like instructions rather than documentation, and declared permissions that
contradict described behaviour.

Plenty of MCP work happens in Node, so `npx …` is a shape people reach for.
The scanner itself is Python on purpose — standard library only, no wheels to
build, no model provider, deterministic output. (Python is not the minority
choice here: the Python MCP SDKs appear in more public source than the
TypeScript one, so this launcher is a convenience, not the main channel.)

## Use

```bash
pip install mcpsurface                        # the scanner itself is Python
npx @baroqueworks/mcpsurface smithery:exa
```

Or install once and use the short command:

```bash
npm i -g @baroqueworks/mcpsurface
mcpsurface smithery:gmail --json              # machine report
mcpsurface smithery:exa --fail-on high        # CI gate
```

> **On the scope:** the npm registry blocks the unscoped name `mcpsurface` as
> too similar to an unrelated package, so this launcher is published under a
> scope. The command it installs is plain `mcpsurface`, and the Python package
> on PyPI is `mcpsurface` — one name everywhere except the npm coordinate.

If Python lives somewhere unusual, point at it directly:

```bash
MCPSURFACE_PYTHON=/opt/homebrew/bin/python3 npx @baroqueworks/mcpsurface smithery:exa
```

## Exit codes

Forwarded verbatim from the Python CLI, because CI keys off them:

| code | meaning |
|---|---|
| `0` | clean, or all findings below `--fail-on` |
| `2` | a finding at or above `--fail-on` (default `high`) |
| `1` | operational error — including "no Python found" or "package not installed" |

The launcher never synthesises an exit code from a successful run. If the
scanner exits 2, so does this.

## What it does and doesn't do

It finds a suitable interpreter (`$MCPSURFACE_PYTHON`, then `python3` /
`python`, or `py -3` on Windows), checks the version and that `mcpsurface` is
importable, then hands over with stdio inherited.

It will **not** install the Python package for you. Writing to someone's Python
environment as a side effect of an `npx` invocation is surprising, and the
right target — venv, `--user`, pipx, uv — is a judgement only you can make. If
the package is missing it prints the commands and exits 1.

## Everything else

Detector documentation, the calibration corpus, the report schema and
contributing guidelines live in the main repository:
**https://github.com/Sra1Phani/mcpsurface**

Apache-2.0. Copyright 2026 Sravan Phani Kumar Vidiyala.
