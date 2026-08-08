"""Normalization and segment extraction for attacker-controlled text.

Two jobs, both consequences of one fact: every string a detector matches
against was written by the server under audit.

**Normalization.** Patterns are written against ordinary prose, so the raw
string is folded before matching — Unicode NFKC, confusable letters mapped
to their Latin lookalikes, invisible characters removed, runs of spaces
collapsed. Without this, `Ignore  previous` (two spaces), `Ignore\\nprevious`,
`Ign\\u200bore` and `Ign\\u043ere` (Cyrillic o) each walk past a pattern that
catches `Ignore previous`. Folding once, centrally, is what keeps that from
being a per-regex problem that every future detector re-introduces.

Detectors that hunt for *characters* rather than words — hidden/bidi
control chars, mixed scripts — must read the RAW text instead. Normalizing
first is exactly what would erase their evidence.

**Segment extraction.** A tool's `description` is not the only untrusted
text the agent reads into its context: the tool name and every
`description` / `title` in the input schema land there too, and parameter
descriptions are a documented poisoning vector precisely because they are
less visible to human review. `collect_text_segments` yields all of them
with a dotted location, so a finding can say where it came from.
"""
from __future__ import annotations

import re
import unicodedata
from typing import Any, Iterable

# Traversal bounds. The input schema comes from a potentially hostile server:
# it can be enormous, deeply nested, or self-referential. Hitting a bound is
# reported (INJ.SCHEMA_TRUNCATED), never silently swallowed.
MAX_SCHEMA_NODES = 512
MAX_SCHEMA_DEPTH = 12

#: Schema keys whose string values are prose shown to the model.
_TEXT_KEYS = ("description", "title")

# --- invisible characters ---------------------------------------------------

#: Zero-width / bidi / control characters used to hide text from human review.
HIDDEN_CHARS = frozenset(
    "​‌‍⁠﻿"      # zero-width family
    "‪‫‬‭‮"      # bidi overrides
    "⁦⁧⁨⁩"            # bidi isolates
    "­"                              # soft hyphen
)

# --- confusables ------------------------------------------------------------
#
# NFKC does not fold Cyrillic/Greek lookalikes onto Latin — by design, they are
# genuinely different letters. For *matching* we want them folded anyway, so a
# homoglyph can't hide an imperative. This is a deliberately small table of the
# letters that actually appear in Latin-lookalike attacks, not a general
# transliteration.
_CONFUSABLES = {
    # Cyrillic → Latin
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "у": "y", "х": "x", "і": "i", "ѕ": "s", "ј": "j",
    "һ": "h", "ӏ": "l", "ԁ": "d", "к": "k", "м": "m",
    "т": "t", "в": "b", "н": "h", "г": "r", "ё": "e",
    # Greek → Latin
    "ο": "o", "α": "a", "ε": "e", "ρ": "p", "ι": "i",
    "ν": "v", "τ": "t", "κ": "k", "χ": "x", "υ": "u",
    "Α": "a", "Β": "b", "Ε": "e", "Ζ": "z", "Η": "h",
    "Ι": "i", "Κ": "k", "Μ": "m", "Ν": "n", "Ο": "o",
    "Ρ": "p", "Τ": "t", "Υ": "y", "Χ": "x",
}
# Uppercase Cyrillic maps to the same Latin letters as its lowercase form.
_CONFUSABLES.update({
    "А": "a", "Е": "e", "О": "o", "Р": "p", "С": "c",
    "У": "y", "Х": "x", "І": "i", "Ѕ": "s", "К": "k",
    "М": "m", "Т": "t", "В": "b", "Н": "h", "Г": "r",
})

_HORIZONTAL_WS = re.compile(r"[^\S\n]+")   # spaces/tabs, but not newlines
_VERTICAL_WS = re.compile(r"\n{2,}")

#: Single translation table: invisibles deleted, confusables folded. Applied
#: with str.translate (one C-level pass) rather than a per-character
#: comprehension — description length is attacker-controlled, so the constant
#: factor on this path is a denial-of-service surface, not just a nicety.
_TRANSLATION = {ord(c): None for c in HIDDEN_CHARS}
_TRANSLATION.update({ord(k): v for k, v in _CONFUSABLES.items()})


def normalize(text: str) -> str:
    """Fold attacker-controlled text into the form the patterns are written for.

    NFKC → strip invisibles → fold confusables → collapse horizontal runs to a
    single space (newlines survive, because the clause splitter uses them as a
    boundary). Idempotent.
    """
    if not text:
        return ""
    text = unicodedata.normalize("NFKC", text).translate(_TRANSLATION)
    text = _HORIZONTAL_WS.sub(" ", text)
    return _VERTICAL_WS.sub("\n", text).strip()


def hidden_characters(text: str) -> list[str]:
    """Unicode names of the invisible characters present in RAW text, sorted."""
    return [unicodedata.name(c, repr(c)) for c in sorted(set(text) & HIDDEN_CHARS)]


# --- mixed-script detection -------------------------------------------------

def _script(ch: str) -> str | None:
    """Coarse script bucket for a letter; None for anything not a cased letter."""
    if not ch.isalpha():
        return None
    cp = ord(ch)
    if cp < 0x0250 or 0x1E00 <= cp <= 0x1EFF:
        return "latin"
    if 0x0370 <= cp <= 0x03FF or 0x1F00 <= cp <= 0x1FFF:
        return "greek"
    if 0x0400 <= cp <= 0x052F:
        return "cyrillic"
    return None


_WORD = re.compile(r"\w+", re.UNICODE)


def mixed_script_words(text: str) -> list[str]:
    """Words that mix Latin with Cyrillic/Greek letters — the homoglyph tell.

    Only *intra-word* mixing counts. A description written in Russian, or one
    that mentions a Latin product name alongside Greek text, mixes scripts
    across words and is perfectly ordinary; a single word containing both
    `a` and `\\u0430` is not.
    """
    out = []
    for word in _WORD.findall(text):
        scripts = {s for s in (_script(c) for c in word) if s}
        if len(scripts) > 1 and "latin" in scripts:
            out.append(word)
    return out


# --- segment extraction -----------------------------------------------------

def collect_text_segments(tool: Any) -> tuple[list[tuple[str, str]], bool]:
    """All model-visible text on a tool, as (location, raw_text) pairs.

    Returns the segments and a `truncated` flag — True when the input schema
    exceeded MAX_SCHEMA_NODES / MAX_SCHEMA_DEPTH, or contained a cycle, so the
    caller can report the gap instead of implying full coverage.
    """
    segments: list[tuple[str, str]] = []
    if tool.name:
        segments.append(("name", tool.name))
    if tool.description:
        segments.append(("description", tool.description))

    truncated = False
    seen: set[int] = set()
    budget = MAX_SCHEMA_NODES

    def walk(node: Any, path: str, depth: int) -> None:
        nonlocal truncated, budget
        if depth > MAX_SCHEMA_DEPTH:
            truncated = True
            return
        if budget <= 0:
            truncated = True
            return
        if isinstance(node, dict):
            if id(node) in seen:          # self-referential schema
                truncated = True
                return
            seen.add(id(node))
            budget -= 1
            for key, value in node.items():
                if key in _TEXT_KEYS and isinstance(value, str) and value.strip():
                    segments.append((f"{path}.{key}", value))
                elif isinstance(value, (dict, list)):
                    walk(value, f"{path}.{key}", depth + 1)
        elif isinstance(node, list):
            if id(node) in seen:
                truncated = True
                return
            seen.add(id(node))
            budget -= 1
            for i, value in enumerate(node):
                if isinstance(value, (dict, list)):
                    walk(value, f"{path}[{i}]", depth + 1)

    if isinstance(tool.input_schema, (dict, list)):
        walk(tool.input_schema, "inputSchema", 0)

    return segments, truncated


def iter_segments(tools: Iterable[Any]) -> Iterable[tuple[Any, str, str]]:
    """(tool, location, raw_text) across every tool. Convenience for detectors."""
    for tool in tools:
        segments, _ = collect_text_segments(tool)
        for location, raw in segments:
            yield tool, location, raw
