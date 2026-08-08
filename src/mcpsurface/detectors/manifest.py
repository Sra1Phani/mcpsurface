"""Manifest integrity checks against .well-known/mcp.json.

v0 scope: presence, expiry, same-origin vs cross-origin, and the
capability-digest diff (declared tool-set hash vs. the live one). The
signature verification against a DNS-published key is stubbed — it needs
a DNS resolver + ed25519 verify and is deliberately left as the first
"good first issue" rather than faked.

Cross-origin *attestation* (shop != platform) is explicitly NOT here.
That's a separate, harder spec; v0 only flags that cross-origin is in play.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Optional, Tuple
from urllib.parse import urlsplit

from .base import Detector
from ..models import Finding, ScanContext, Severity

#: Ports that are implicit in a URL, so `https://e.com` == `https://e.com:443`.
_DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443}

Origin = Tuple[str, str, Optional[int]]


def _origin_of(url: str) -> Optional[Origin]:
    """(scheme, host, effective port), or None if `url` isn't a usable origin.

    Returning None for "e.com" or "" matters: "I cannot compare these origins"
    is a different fact from "these origins differ", and the detector reports
    them as different findings rather than collapsing the first into the second.
    """
    if not url:
        return None
    parts = urlsplit(url.strip())
    scheme, host = parts.scheme.lower(), parts.hostname
    if not scheme or not host:
        return None
    try:
        port = parts.port
    except ValueError:      # malformed port, e.g. "https://e.com:notaport"
        return None
    return (scheme, host, port if port is not None else _DEFAULT_PORTS.get(scheme))


def _same_origin(a: str, b: str) -> bool:
    """True iff two URLs share scheme + host + effective port.

    A prefix/startswith comparison is unsafe: "https://shop.example.com.evil.com"
    starts with "https://shop.example.com" yet is a different origin. Compare the
    parsed origin tuple so a suffix-domain attacker can't pass. Default ports are
    filled in first, so `https://e.com` and `https://e.com:443` — the same
    origin, written two ways — don't read as cross-origin.

    Unusable input is False (not same-origin), never True; callers that need to
    distinguish "differs" from "can't tell" should use `_origin_of` directly.
    """
    oa = _origin_of(a)
    return oa is not None and oa == _origin_of(b)


def _parse_timestamp(value: str) -> Optional[datetime]:
    """Parse an ISO-8601 manifest timestamp, or None if it isn't one.

    `datetime.fromisoformat` gained "Z" support only in 3.11 and this package
    supports 3.9, so the suffix is rewritten first. A timestamp with no zone is
    read as UTC — manifests are machine-written and a naive local reading would
    make expiry depend on where the scanner runs.
    """
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def capability_digest(ctx: ScanContext) -> str:
    """Deterministic hash of the live tool set, to compare against the manifest.

    NOTE: this only matches a manifest's capabilities_digest when the manifest
    author used *this exact scheme* — sorted {name, description} pairs, compact
    JSON, sha256. There is no standardized canonicalization for MCP capability
    digests, so a mismatch against a third-party manifest is expected, not
    evidence of a rug-pull. That is why MANIFEST.DIGEST_MISMATCH is LOW and
    never gates (see ManifestDetector.run).
    """
    payload = sorted(
        ({"name": t.name, "description": t.description} for t in ctx.tools),
        key=lambda d: d["name"],
    )
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(blob).hexdigest()


class ManifestDetector(Detector):
    id = "manifest"
    title = "Manifest integrity (.well-known/mcp.json)"

    def run(self, ctx: ScanContext) -> list[Finding]:
        m = ctx.manifest
        out: list[Finding] = []

        if not ctx.manifest_available:
            # Never fetched, so "absent" would be an assertion we cannot make.
            return [Finding(
                detector_id=self.id, code="MANIFEST.NOT_CHECKED", severity=Severity.INFO,
                message="This source does not fetch .well-known/mcp.json, so "
                        "manifest integrity was not checked. The manifest may "
                        "exist; it was not looked for.",
            )]

        if not m.present:
            out.append(Finding(
                detector_id=self.id, code="MANIFEST.ABSENT", severity=Severity.INFO,
                message="No .well-known/mcp.json found. Server is unsigned/undeclared; "
                        "discovery cannot be verified.",
            ))
            return out

        # Expiry. Three distinct facts, three distinct codes — "no expiry
        # field", "unparseable expiry" and "expired" are not the same problem,
        # and an expired manifest must not read as silence.
        if not m.expires:
            out.append(Finding(
                detector_id=self.id, code="MANIFEST.NO_EXPIRY", severity=Severity.MEDIUM,
                message="Manifest has no expiry; a stale manifest can be replayed.",
            ))
        else:
            expires_at = _parse_timestamp(m.expires)
            if expires_at is None:
                out.append(Finding(
                    detector_id=self.id, code="MANIFEST.BAD_EXPIRY",
                    severity=Severity.MEDIUM, evidence=str(m.expires)[:64],
                    message="Manifest expiry is not a parseable ISO-8601 timestamp, "
                            "so it cannot be enforced — treat it as absent.",
                ))
            elif expires_at <= datetime.now(timezone.utc):
                out.append(Finding(
                    detector_id=self.id, code="MANIFEST.EXPIRED",
                    severity=Severity.MEDIUM, evidence=expires_at.isoformat(),
                    message="Manifest expired. The declaration it makes about this "
                            "server is no longer valid and may be a replay of an "
                            "older, differently-scoped manifest.",
                ))

        # Origin binding. "Can't compare" and "cross-origin" are separate
        # findings: a scheme-less or malformed origin is a manifest defect, not
        # evidence that the server is somewhere else.
        if m.origin and m.server_url:
            declared, claimed = _origin_of(m.server_url), _origin_of(m.origin)
            if declared is None or claimed is None:
                out.append(Finding(
                    detector_id=self.id, code="MANIFEST.MALFORMED_ORIGIN",
                    severity=Severity.MEDIUM,
                    evidence=f"origin={m.origin!r} server_url={m.server_url!r}",
                    message="Manifest origin or server_url is not a usable absolute "
                            "URL, so the origin binding cannot be checked at all.",
                ))
            elif declared != claimed:
                out.append(Finding(
                    detector_id=self.id, code="MANIFEST.CROSS_ORIGIN",
                    severity=Severity.MEDIUM,
                    evidence=f"{m.origin} -> {m.server_url}",
                    message="Declared server is cross-origin from the manifest origin. "
                            "Requires cross-origin attestation (out of v0 scope) to trust.",
                ))

        # Capability digest diff (rug-pull / silent expansion)
        if m.capabilities_digest:
            live = capability_digest(ctx)
            if live != m.capabilities_digest:
                out.append(Finding(
                    detector_id=self.id, code="MANIFEST.DIGEST_MISMATCH",
                    severity=Severity.LOW, evidence=f"declared={m.capabilities_digest} "
                                                    f"live={live}",
                    message="[experimental] Live tool set does not match the manifest's "
                            "capabilities_digest. This only indicates silent expansion / "
                            "rug-pull when the manifest author used this scanner's exact "
                            "digest scheme; absent a standardized canonicalization it "
                            "false-fires on third-party manifests, so it is LOW and never "
                            "gates --fail-on at the default.",
                ))

        # Signature — TODO: resolve DNS key, ed25519 verify. Don't fake a pass.
        if m.signature_verified is None:
            out.append(Finding(
                detector_id=self.id, code="MANIFEST.SIG_UNVERIFIED", severity=Severity.LOW,
                message="Signature not verified (DNS-key verification not yet "
                        "implemented). Treat the manifest as unauthenticated.",
            ))
        elif m.signature_verified is False:
            out.append(Finding(
                detector_id=self.id, code="MANIFEST.SIG_INVALID", severity=Severity.CRITICAL,
                message="Manifest signature failed verification.",
            ))
        return out
