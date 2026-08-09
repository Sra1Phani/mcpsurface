#!/usr/bin/env node
'use strict';

// Launcher for the Python `mcpsurface` CLI.
//
// Plenty of MCP work happens in Node, so `npx …` is a shape people reach for.
// The scanner itself is Python, deliberately: standard library only, no wheels
// to build, deterministic. Python is not the minority choice in MCP, so this is
// a convenience entry point rather than the primary channel — it forwards to
// the real CLI and does nothing clever in between.
//
// The one thing it must not get wrong is the **exit code**. mcpsurface's
// contract is 0 clean / 2 a finding at or above --fail-on / 1 operational
// error, and CI keys off that split. A launcher that collapses those into
// "worked / didn't" would silently break every pipeline using it, so the
// child's status is propagated verbatim and never synthesised.

const { spawnSync } = require('node:child_process');

const MIN_PYTHON = [3, 9];

/** The Python module this launches. Same on PyPI, unscoped. */
const MODULE = 'mcpsurface';

// Read the npm coordinate rather than hard-coding it: the registry blocks the
// unscoped name, so this package is scoped while the Python package and the
// installed command are not. Deriving it means a help message can never
// advertise an `npx` target that does not resolve.
const NPM_NAME = require('../package.json').name;

// Exit codes owned by *this* launcher. 1 overlaps mcpsurface's "operational
// error", which is correct: failing to find an interpreter is exactly that.
const EXIT_LAUNCHER_ERROR = 1;

/** Interpreters to try, each as [command, ...leadingArgs]. */
function interpreterCandidates() {
  const override = process.env.MCPSURFACE_PYTHON;
  if (override) return [[override]];
  return process.platform === 'win32'
    ? [['py', '-3'], ['python'], ['python3']]
    : [['python3'], ['python']];
}

// One probe answers both questions — interpreter version and whether the
// package is importable — so we spawn once per candidate rather than twice.
// find_spec, not `import mcpsurface`: it answers "is it importable" without
// executing the package, which keeps the probe fast and side-effect free.
const PROBE = 'import sys, importlib.util as u; ' +
  `print(sys.version_info[0], sys.version_info[1], 1 if u.find_spec("${MODULE}") else 0)`;

function probe(cmd, pre) {
  const res = spawnSync(cmd, [...pre, '-c', PROBE], {
    encoding: 'utf8',
    windowsHide: true,
  });
  if (res.error || res.status !== 0 || !res.stdout) return null;
  const [major, minor, hasPkg] = res.stdout.trim().split(/\s+/).map(Number);
  if (!Number.isInteger(major) || !Number.isInteger(minor)) return null;
  return { cmd, pre, version: [major, minor], installed: hasPkg === 1 };
}

function meetsMinimum([major, minor]) {
  return major > MIN_PYTHON[0] ||
    (major === MIN_PYTHON[0] && minor >= MIN_PYTHON[1]);
}

function fail(lines) {
  for (const line of lines) console.error(line);
  process.exit(EXIT_LAUNCHER_ERROR);
}

function main() {
  const found = [];
  for (const [cmd, ...pre] of interpreterCandidates()) {
    const info = probe(cmd, pre);
    if (info) found.push(info);
  }

  if (found.length === 0) {
    fail([
      'mcpsurface: no Python interpreter found.',
      '',
      'This package is a launcher; the scanner itself is Python ' +
        `${MIN_PYTHON.join('.')}+.`,
      'Install Python, or point at one explicitly:',
      '',
      `    MCPSURFACE_PYTHON=/path/to/python npx ${NPM_NAME} …`,
    ]);
  }

  // Prefer an interpreter that already has the package, so we never report
  // "not installed" while a perfectly good install sits on the next candidate.
  const usable = found.filter((f) => meetsMinimum(f.version));
  const chosen = usable.find((f) => f.installed) || usable[0];

  if (!chosen) {
    fail([
      `mcpsurface: needs Python ${MIN_PYTHON.join('.')} or newer.`,
      '',
      'Found: ' + found
        .map((f) => `${f.cmd} (${f.version.join('.')})`)
        .join(', '),
    ]);
  }

  if (!chosen.installed) {
    // Deliberately not auto-installing. Writing to someone's Python
    // environment from a Node launcher is a surprising side effect, and the
    // right target (venv, --user, pipx, uv) is a judgement only they can make.
    fail([
      `mcpsurface: the Python package is not installed for ${chosen.cmd}.`,
      '',
      'Install it with one of:',
      '',
      `    ${chosen.cmd} -m pip install ${MODULE}`,
      `    pipx install ${MODULE}`,
      `    uv tool install ${MODULE}`,
      '',
      'Then re-run this command.',
    ]);
  }

  // `-m mcpsurface.cli` rather than the console script: it does not depend on
  // the script directory being on PATH, which is exactly the case that breaks
  // inside npx, CI containers, and conda environments.
  const res = spawnSync(chosen.cmd, [...chosen.pre, '-m', `${MODULE}.cli`,
    ...process.argv.slice(2)], { stdio: 'inherit', windowsHide: true });

  if (res.error) {
    fail([`mcpsurface: failed to run ${chosen.cmd}: ${res.error.message}`]);
  }
  if (res.status === null) {
    // Killed by a signal. Report it the way a shell would (128 + signal), so
    // Ctrl-C reads as an interrupt rather than as a clean scan.
    const signals = { SIGINT: 2, SIGTERM: 15, SIGHUP: 1, SIGQUIT: 3 };
    process.exit(128 + (signals[res.signal] || 0));
  }
  process.exit(res.status);
}

main();
