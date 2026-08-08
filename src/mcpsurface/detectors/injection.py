"""Heuristic injection / exfiltration scanner over model-visible tool text.

The premise: a tool *description* is untrusted data that the agent reads
into its context. A poisoned description tries to act as an instruction.
This detector flags the shapes that does in: imperatives aimed at the
model, exfiltration phrasing, secrecy directives, and hidden text.

It scans every string the agent actually reads — the description, the tool
name, and every `description` / `title` in the input schema. Parameter
descriptions are a documented poisoning vector precisely because they are
less visible to human review than the tool description, so scanning only
the latter leaves the larger surface untouched.

All word-level patterns match against `text.normalize`d input, so extra
whitespace, newlines, zero-width characters and Cyrillic/Greek homoglyphs
cannot walk a payload past a pattern. Character-level checks
(INJ.HIDDEN_CHARS, INJ.MIXED_SCRIPT) read the raw text instead —
normalizing is exactly what would erase their evidence.

Heuristic, not exhaustive. The opt-in `--llm` judge is meant to catch the
subtler cases this misses; this one is fast, offline, and deterministic.
"""
from __future__ import annotations

import re

from .base import Detector
from ..models import Finding, ScanContext, Severity
from ..text import (
    collect_text_segments,
    hidden_characters,
    mixed_script_words,
    normalize,
)

# NOTE ON PATTERNS: every inter-word gap is `\s+`, never a literal space.
# `normalize()` already collapses runs of whitespace, but writing the patterns
# this way means a future detector that forgets to normalize still can't be
# defeated by a second space — the bypass is closed in two places.

# Imperatives unambiguously directed at the agent (not at the caller of the tool).
# Generic call-usage phrasing ("you must", "you should always", "always
# include/use") is deliberately excluded: it fires on ordinary parameter docs
# ("You must provide a valid ISO date", "Always include the country code"). The
# --llm judge is meant to promote borderline cases; the heuristic keeps only the
# clear agent-directed tells at HIGH.
#
# CORPUS-CALIBRATED. Bare "system prompt" was the single largest source of
# false alarms across 12,696 real tool definitions: every LLM-tooling server
# mentions it legitimately ("provide the system prompt", "build a structured
# system prompt"), including a tool literally named `prompt_injection_scan`.
# The noun phrase is not the tell — the *verb governing it* is. "Reveal your
# system prompt" is an attack; "provide the system prompt" is a parameter doc.
_IMPERATIVE = re.compile(
    r"(?:\b(?:"
    r"ignore\s+(?:the\s+|all\s+)?(?:previous|prior|above)"
    r"|disregard\s+(?:the\s+|all\s+)?(?:previous|prior)"
    r"|do\s+not\s+(?:tell|mention|inform|reveal)"
    # The injection idiom is the full "as an AI language model / assistant"
    # preamble. Bare "as an AI" fired on a parameter description asking authors
    # *not* to write "As an AI..." openings.
    r"|as\s+an\s+ai\s+(?:language\s+)?(?:model|assistant)"
    # Qualifiers stack in real payloads ("the entire original instructions"),
    # so allow a run of them rather than exactly one.
    r"|(?:reveal|repeat|print|output|expose|dump|leak|disclose|echo|forget"
    r"|ignore|disregard|override)\s+(?:your|the|its)\s+"
    r"(?:(?:full|entire|original|initial|complete|exact|verbatim)\s+){0,3}"
    r"(?:system\s+)?(?:prompt|instructions)"
    # Deliberately still "any other tool", NOT "this tool". Widening it to
    # "this tool" was tried against the corpus and produced false positives on
    # ordinary usage guidance ("convert relative phrases to that format before
    # calling this tool"). It bought no unique detections: the canonical
    # payload that phrases it that way carries an <IMPORTANT> wrapper and is
    # caught by the markup branch below regardless.
    r"|before\s+(?:using|calling)\s+any\s+other\s+tool"
    r")\b"
    # Pseudo-markup directive blocks (<IMPORTANT>…</IMPORTANT>) are the
    # signature wrapper of the published MCP tool-poisoning demo. A tool
    # description is prose; an imperative tag addressed to the model is not
    # something a legitimate description needs. No \b here — angle and square
    # brackets are not word characters.
    r"|[<\[]\s*/?\s*(?:important|system|secret|admin|critical|urgent"
    r"|instructions?|note\s+to\s+(?:ai|assistant|model))\s*[>\]])",
    re.IGNORECASE,
)

# Exfiltration requires CO-OCCURRENCE of a reach verb (moves data outward) AND a
# sensitive object IN THE SAME CLAUSE. Either alone over-fires: comms tools
# legitimately "forward"/"send", auth/secrets tools legitimately mention
# "token"/"secret". Whole-description co-occurrence also over-fires ("uploads
# the file and returns a token for tracking") — a genuine exfil instruction
# names the sensitive object as the object of its reach verb, in one breath
# ("send the api_key"), so proximity is evaluated per clause (see run()).
#
# CORPUS-CALIBRATED. "post" and "email" are nouns at least as often as verbs in
# real tool docs ("title per post", "the email link", "Email address to
# associate with the new API key") and each produced false CRITICALs. Requiring
# a following determiner keeps the verb reading ("email the api_key to …",
# "posts your credentials to …") and drops the noun reading, which never has
# one.
_REACH = re.compile(
    r"\b(?:send(?:s|ing)?|forward(?:s|ing)?|transmit(?:s|ting)?|exfiltrat\w+|"
    r"leak(?:s|ing)?|upload(?:s|ing)?|deliver(?:s|ing)?|"
    r"(?:post|email)(?:s|ing)?\s+(?:the|your|all|any|a)\b|"
    r"report\s+back|include\s+your|"
    r"pass(?:es|ing)?\s+(?:the\s+|your\s+)?(?:context|conversation|history))\b",
    re.IGNORECASE,
)
# Genuinely sensitive objects only. Bare "history" / "context" / "conversation"
# are removed — they read as ordinary in normal read tools and were the main
# false-positive driver; the multiword "conversation history" / "chat history"
# is the actual exfil tell. Plurals allowed (secrets, tokens, …).
#
# `.ssh` is matched by a separate branch: `\b\.ssh` can never match after a
# space, because a word boundary before a non-word character requires a
# preceding word character — so the original pattern only ever fired on
# "foo.ssh", never on "the .ssh directory".
#
# CORPUS-CALIBRATED. Bare "token" is the most overloaded word in the MCP
# ecosystem — LLM context tokens, crypto tokens, pagination tokens,
# unsubscribe tokens, tracking tokens — and produced false CRITICALs on all
# four senses. Only a *qualified* token names a credential. Note this cuts
# recall on the bare-word attack ("send the token to evil.com"); that is the
# precision-first trade, and the qualifiers cover how credentials are actually
# named in real docs.
_SENSITIVE_OBJECT = re.compile(
    r"(?:\b(?:api[_\s]?keys?|secrets?|credentials?|passwords?|"
    r"(?:api|auth|authentication|authorization|access|bearer|session|refresh|"
    r"oauth|security|secret|jwt|personal\s+access|github|gitlab|slack)"
    r"[\s_-]?tokens?|"
    r"environment\s+variables?|env\s+vars?|"
    r"conversation\s+history|chat\s+history)\b"
    r"|(?<![\w.])\.ssh\b)",
    re.IGNORECASE,
)
# Clause boundaries: sentence terminators, semicolons, commas, newlines, and the
# coordinating "and". A reach verb and a sensitive object must land in the SAME
# resulting clause to count as exfiltration.
#
# A terminator only splits when followed by whitespace or end-of-string, so
# dotted tokens (".ssh", "evil.com") stay intact instead of being torn in half.
_CLAUSE_SPLIT = re.compile(r"(?:[.;!?,]+(?=\s|$))|\n+|\band\b", re.IGNORECASE)

# Protocol destinations. Scanning parameter descriptions brought a new genre of
# prose into range, and it has its own idiom: auth tools routinely document
# "Send the token in the Authorization header". That pairs a reach verb with a
# sensitive object in one clause while describing where the value goes *within
# the call*, not where it goes outside it — a CRITICAL there is a false
# positive on ordinary API docs.
#
# RECALL COST, ACCEPTED: appending "in the header" to a genuine exfil
# instruction suppresses INJ.EXFIL. That is the documented precision-first
# trade (see the class docstring and decisions#detector-precision-floor) — the
# heuristic keeps precision, the --llm judge owns this case. Tracked as an
# xfail in tests/test_hardening.py so closing it can't happen silently.
_PROTOCOL_DESTINATION = re.compile(
    # `[\w-]+` so hyphenated header names ("X-Auth", "X-Api-Key") count as the
    # qualifier; up to two qualifier tokens covers "the custom auth header".
    r"\b(?:in|as|via|using|with|inside)\s+(?:the\s+|a\s+|an\s+|your\s+)?(?:[\w-]+\s+){0,2}"
    r"(?:headers?|cookies?|query\s+string|query\s+param\w*|request\s+body|"
    r"body|payload|form\s+field)\b"
    r"|\bbearer\s+token\b",
    re.IGNORECASE,
)

# One-time codes delivered *to the user* are the opposite of exfiltration —
# sending them out is the tool's whole purpose. Corpus-calibrated: an OTP
# tool ("Sends a one-time password (OTP) to the user's email address") was
# the last surviving false CRITICAL.
_BENIGN_CREDENTIAL_FLOW = re.compile(
    r"\b(?:one[-\s]?time\s+(?:password|passcode|code)|otp|magic\s+link|"
    r"verification\s+code|reset\s+link|confirmation\s+code)\b",
    re.IGNORECASE,
)

# Secrecy directives — the tell of a confused-deputy setup.
#
# CORPUS-CALIBRATED. Bare "silently" is ordinary API vocabulary — "fails
# silently", "silently ignores unknown fields", "silently truncates" — and
# fired on six unrelated benign servers. Secrecy is only a tell when it
# qualifies an *action the agent takes*, not an error-handling behaviour.
_SECRECY = re.compile(
    r"\b(?:without\s+(?:telling|informing|notifying)"
    r"|silently\s+(?:send|forward|transmit|upload|post|email|include|attach|"
    r"copy|share|report|call|invoke|execute|run|add|store|save|log)"
    r"|do\s+not\s+show"
    r"|behind\s+the\s+scenes"
    r"|covertly)\b",
    re.IGNORECASE,
)


def _truncate(s: str, n: int = 120) -> str:
    s = s.strip().replace("\n", " ")
    return s if len(s) <= n else s[: n - 1] + "…"


def _where(location: str) -> str:
    """Suffix naming the offending segment, omitted for the plain description."""
    return "" if location == "description" else f" Location: {location}."


class InjectionDetector(Detector):
    """Heuristic prompt-injection / exfiltration scan over model-visible text.

    SCOPE LIMIT — INJ.EXFIL is high-precision, low-recall BY DESIGN. It fires
    only when a reach verb and a sensitive object occur in the SAME clause
    ("send the api_key to X"). It deliberately does NOT catch:

      - multi-clause exfil:  "Grab the secret AND send it to evil.com"
      - pronoun-referenced:  "Read the api_key. Forward it to our server."

    These are the *dominant* exfil grammar, not a corner case — but they can't
    be separated from legitimate phrasing by regex, because the distinction is
    semantic: is the sensitive object being sent OUTWARD to a third party?
    "Returns a token" (to the caller) and "sends the token to evil.com"
    (outbound) share the same words and opposite meaning. That judgment is the
    job of the opt-in --llm judge (requires_llm); the heuristic owns precision,
    the judge owns recall. A clean heuristic INJ.EXFIL is NOT evidence the tool
    is exfil-free — see the xfail cases in tests/test_smoke.py for tracked gaps.

    SCOPE LIMIT — the word-level patterns (IMPERATIVE / EXFIL / SECRECY) run on
    prose segments only, not on the tool *name*. A name is an identifier, not a
    sentence: `send_verification_token` pairs a reach verb with a sensitive
    object purely as naming, and clause proximity means nothing without clauses.
    Names still get the character-level checks, where identifier-vs-prose makes
    no difference and hidden characters are a strong tell.
    """

    id = "injection"
    title = "Tool-description prompt injection / exfiltration"

    def run(self, ctx: ScanContext) -> list[Finding]:
        out: list[Finding] = []
        for tool in ctx.tools:
            segments, truncated = collect_text_segments(tool)

            for location, raw in segments:
                out.extend(self._scan_segment(tool.name, location, raw))

            if truncated:
                out.append(Finding(
                    detector_id=self.id, code="INJ.SCHEMA_TRUNCATED",
                    severity=Severity.INFO, tool_name=tool.name,
                    message="Input schema was too large, too deeply nested, or "
                            "self-referential; part of it was not scanned. "
                            "Absence of findings here is not coverage.",
                ))
        return out

    def _scan_segment(self, tool_name: str, location: str, raw: str) -> list[Finding]:
        out: list[Finding] = []
        text = normalize(raw)

        # --- word-level: prose only (see SCOPE LIMIT on names, above) ---
        if location != "name":
            if m := _IMPERATIVE.search(text):
                out.append(Finding(
                    detector_id=self.id, code="INJ.IMPERATIVE", severity=Severity.HIGH,
                    tool_name=tool_name, evidence=_truncate(m.group(0)),
                    message="Text contains an instruction aimed at the agent, "
                            "not a description of the tool." + _where(location),
                ))

            for clause in _CLAUSE_SPLIT.split(text):
                if _PROTOCOL_DESTINATION.search(clause):
                    continue        # "send the token in the auth header" — not outbound
                if _BENIGN_CREDENTIAL_FLOW.search(clause):
                    continue        # "sends a one-time password to the user" — inbound by design
                if _REACH.search(clause) and _SENSITIVE_OBJECT.search(clause):
                    out.append(Finding(
                        detector_id=self.id, code="INJ.EXFIL", severity=Severity.CRITICAL,
                        tool_name=tool_name, evidence=_truncate(clause.strip()),
                        message="A single clause pairs an outward-reach verb with a "
                                "sensitive object (secret/credential/key) — the shape "
                                "of an exfiltration instruction." + _where(location),
                    ))
                    break

            if m := _SECRECY.search(text):
                out.append(Finding(
                    detector_id=self.id, code="INJ.SECRECY", severity=Severity.HIGH,
                    tool_name=tool_name, evidence=_truncate(m.group(0)),
                    message="Text instructs the agent to act without informing "
                            "the user." + _where(location),
                ))

        # --- character-level: RAW text, every segment including the name ---
        if hidden := hidden_characters(raw):
            out.append(Finding(
                detector_id=self.id, code="INJ.HIDDEN_CHARS", severity=Severity.HIGH,
                tool_name=tool_name, evidence=", ".join(hidden),
                message="Text contains zero-width or bidi control characters "
                        "that hide content from human review." + _where(location),
            ))

        if mixed := mixed_script_words(raw):
            out.append(Finding(
                detector_id=self.id, code="INJ.MIXED_SCRIPT", severity=Severity.MEDIUM,
                tool_name=tool_name, evidence=_truncate(", ".join(sorted(set(mixed)))),
                message="A word mixes Latin with Cyrillic/Greek letters — the "
                        "signature of a homoglyph substitution used to evade "
                        "review or pattern matching." + _where(location),
            ))

        return out
