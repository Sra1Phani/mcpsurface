#!/usr/bin/env python3
"""RECONSTRUCTED pre-calibration detector patterns, for checking the headline.

    python corpus/compare_calibration.py corpus/data/smithery-registry-*.jsonl

WHAT THIS IS, PRECISELY. The published false-alarm rate of 4.3% was measured
before this repository existed. The first commit already contains the
calibrated patterns, so there is no tag to check out that reproduces the
"before" state. The originals are gone.

These are therefore a **reconstruction, not a recovery**. They are rebuilt
from the `CORPUS-CALIBRATED` comments in the detector sources, each of which
records what the pattern used to be and why it changed. That is a strong
reconstruction, but it is an inference about a past state, and inference is
exactly the thing this project exists to be suspicious of.

Treat any number produced here as "what a faithful reconstruction of the old
patterns scores on this corpus", not as "the original measurement". If it
disagrees with 4.3%, the reconstruction is evidence that the published figure
is unverifiable — not evidence that the reconstruction is wrong.

WHAT CHANGED, and therefore what is reverted here (injection.py):

  1. `system prompt` — matched as a bare noun phrase, with no governing verb.
  2. `silently`     — matched bare, with no following action verb.
  3. `tokens?`      — matched bare, unqualified by api/auth/bearer/session/…
  4. `post`/`email` — matched as reach verbs with no following determiner.
  5. `as an ai`     — matched without requiring "language model" / "assistant".
  6. No `<IMPORTANT>`-style pseudo-markup branch at all.
  7. No stacked-qualifier branch ("repeat the entire original instructions").
  8. No `_BENIGN_CREDENTIAL_FLOW` exclusion (one-time passwords, OTP codes).

and (scope_class.py):

  9. `execute`, `drop`, `purchase`, `publish` matched bare, unqualified.
 10. No `_DISCLAIMS_MUTATION` guard, so "Execute a read-only SELECT" counted
     as a mutation.

`_PROTOCOL_DESTINATION` is deliberately NOT reverted: it predates the corpus
work, added during the earlier audit pass, and was present when 4.3% was
measured.
"""
from __future__ import annotations

import re

import mcpsurface.detectors.injection as inj
import mcpsurface.detectors.scope_class as sc

# --- injection.py, as it stood before corpus calibration --------------------

PRE_IMPERATIVE = re.compile(
    r"\b(?:"
    r"ignore\s+(?:the\s+|all\s+)?(?:previous|prior|above)"
    r"|disregard\s+(?:the\s+|all\s+)?(?:previous|prior)"
    r"|do\s+not\s+(?:tell|mention|inform|reveal)"
    r"|as\s+an\s+ai"
    r"|system\s+prompt"
    r"|before\s+(?:using|calling)\s+any\s+other\s+tool"
    r")\b",
    re.IGNORECASE,
)

PRE_REACH = re.compile(
    r"\b(?:send(?:s|ing)?|forward(?:s|ing)?|transmit(?:s|ting)?|exfiltrat\w+|"
    r"leak(?:s|ing)?|upload(?:s|ing)?|post(?:s|ing)?|email(?:s|ing)?|"
    r"deliver(?:s|ing)?|report\s+back|include\s+your|"
    r"pass(?:es|ing)?\s+(?:the\s+|your\s+)?(?:context|conversation|history))\b",
    re.IGNORECASE,
)

PRE_SENSITIVE_OBJECT = re.compile(
    r"(?:\b(?:api[_\s]?keys?|secrets?|tokens?|credentials?|passwords?|"
    r"environment\s+variables?|env\s+vars?|"
    r"conversation\s+history|chat\s+history)\b"
    r"|(?<![\w.])\.ssh\b)",
    re.IGNORECASE,
)

PRE_SECRECY = re.compile(
    r"\b(?:without\s+(?:telling|informing|notifying)|silently|do\s+not\s+show|"
    r"behind\s+the\s+scenes|covertly)\b",
    re.IGNORECASE,
)

# The OTP/one-time-code exclusion did not exist. A pattern that matches
# nothing is the faithful way to disable it without touching detector code.
PRE_BENIGN_CREDENTIAL_FLOW = re.compile(r"(?!x)x")

# --- scope_class.py, as it stood before corpus calibration ------------------

PRE_SIDE_EFFECT = re.compile(
    r"\b(?:delete|remove|drop|destroy|wipe|transfer|send\s+(?:money|funds|payment)|"
    r"pay|purchase|buy|charge|refund|withdraw|deploy|publish|grant|revoke|"
    r"execute|run\s+command|overwrite|reset)\b",
    re.IGNORECASE,
)

# The "the prose says it does not mutate" guard did not exist.
PRE_DISCLAIMS_MUTATION = re.compile(r"(?!x)x")


def apply() -> dict:
    """Swap the reconstructed patterns in. Returns the originals for restore()."""
    saved = {
        "_IMPERATIVE": inj._IMPERATIVE,
        "_REACH": inj._REACH,
        "_SENSITIVE_OBJECT": inj._SENSITIVE_OBJECT,
        "_SECRECY": inj._SECRECY,
        "_BENIGN_CREDENTIAL_FLOW": inj._BENIGN_CREDENTIAL_FLOW,
        "_SIDE_EFFECT": sc._SIDE_EFFECT,
        "_DISCLAIMS_MUTATION": sc._DISCLAIMS_MUTATION,
    }
    inj._IMPERATIVE = PRE_IMPERATIVE
    inj._REACH = PRE_REACH
    inj._SENSITIVE_OBJECT = PRE_SENSITIVE_OBJECT
    inj._SECRECY = PRE_SECRECY
    inj._BENIGN_CREDENTIAL_FLOW = PRE_BENIGN_CREDENTIAL_FLOW
    sc._SIDE_EFFECT = PRE_SIDE_EFFECT
    sc._DISCLAIMS_MUTATION = PRE_DISCLAIMS_MUTATION
    return saved


def restore(saved: dict) -> None:
    inj._IMPERATIVE = saved["_IMPERATIVE"]
    inj._REACH = saved["_REACH"]
    inj._SENSITIVE_OBJECT = saved["_SENSITIVE_OBJECT"]
    inj._SECRECY = saved["_SECRECY"]
    inj._BENIGN_CREDENTIAL_FLOW = saved["_BENIGN_CREDENTIAL_FLOW"]
    sc._SIDE_EFFECT = saved["_SIDE_EFFECT"]
    sc._DISCLAIMS_MUTATION = saved["_DISCLAIMS_MUTATION"]
