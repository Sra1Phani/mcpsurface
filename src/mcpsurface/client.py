"""MCP client — fetches the tool surface and manifest to be scanned.

The public surface (`fetch_tools`, `fetch_manifest`) parses raw transport
payloads into the typed `Tool` / `Manifest` models the detectors consume.
The transport itself is the seam left for live use: `_transport_list_tools`
and `_transport_get_manifest` raise NotImplementedError here. Subclass and
implement them (see tests/test_smoke.py's FixtureClient for the shape, and
the CLI which reports the NotImplementedError as "transport not wired").
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Optional
from urllib.parse import quote

from . import __version__
from .models import Manifest, Tool

#: Target prefix selecting the registry source, e.g. `smithery:exa`.
SMITHERY_PREFIX = "smithery:"

#: Hard cap on a third-party response body (16 MiB).
MAX_RESPONSE_BYTES = 16 * 1024 * 1024


def _as_text(value: Any) -> str:
    """Coerce an arbitrary JSON value to the text a detector can scan.

    `Tool.description` is typed `str`, but the payload it comes from is written
    by the server under audit — nothing stops it being an object, a number, or
    null. Coercing here makes the annotation true for every Tool that exists,
    so no detector can be handed a non-string (which previously raised
    TypeError straight out of the scan).

    Non-strings are serialized rather than dropped: a payload nested inside an
    object is still text the agent may end up reading, so it stays scannable.
    """
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return str(value)


def _as_optional_bool(value: Any) -> Optional[bool]:
    """Real booleans only; anything else is 'not declared'.

    MCP annotation hints gate consent decisions, so `"readOnlyHint": "false"`
    (a string, therefore truthy) must never be read as a declared value. An
    un-typed hint is unknown, not asserted.
    """
    return value if isinstance(value, bool) else None


class MCPClient:
    #: What this source can actually report. A client that reads a second-hand
    #: index cannot see annotations or `.well-known/mcp.json`, and must say so
    #: rather than letting detectors read the gap as an empty declaration.
    supports_annotations: bool = True
    supports_manifest: bool = True

    def __init__(self, target: str) -> None:
        self.target = target

    # --- public: typed surface the runner/detectors consume ---

    def fetch_tools(self) -> list[Tool]:
        entries = self._transport_list_tools() or []
        if not isinstance(entries, list):
            raise ValueError(
                f"tools/list did not return a list (got {type(entries).__name__}); "
                "server response is malformed"
            )
        tools: list[Tool] = []
        for i, raw in enumerate(entries):
            if not isinstance(raw, dict):
                raise ValueError(
                    f"tools/list entry {i} is not a JSON object "
                    f"(got {type(raw).__name__}); server response is malformed"
                )
            tools.append(self._to_tool(raw))
        return tools

    def fetch_manifest(self) -> Manifest:
        raw = self._transport_get_manifest()
        if not raw:
            return Manifest(present=False)
        if not isinstance(raw, dict):
            raise ValueError(
                f"manifest is not a JSON object (got {type(raw).__name__}); "
                "server response is malformed"
            )
        return self._to_manifest(raw)

    # --- transport: stubs. Override these for a live scan. ---
    #
    # TODO(security): the real transport connects to potentially hostile servers.
    # When it lands it MUST:
    #   - set a request timeout (no unbounded hangs);
    #   - cap the response size — a malicious server can return a giant tool
    #     description to OOM the scanner; stream and abort past a sane limit;
    #   - refuse redirects to internal/loopback/link-local addresses (SSRF):
    #     block 127.0.0.0/8, ::1, 169.254.0.0/16, 10/172.16/192.168 and
    #     resolve-then-check the final host, not just the initial URL.

    def _transport_list_tools(self) -> list[dict[str, Any]]:
        """Return the raw `tools/list` entries from the MCP server."""
        raise NotImplementedError(
            "MCP transport not implemented — subclass MCPClient and implement "
            "_transport_list_tools()"
        )

    def _transport_get_manifest(self) -> Optional[dict[str, Any]]:
        """Return the parsed `.well-known/mcp.json`, or None if absent."""
        raise NotImplementedError(
            "MCP transport not implemented — subclass MCPClient and implement "
            "_transport_get_manifest()"
        )

    # --- parsing: raw payload -> typed model ---

    # --- source selection ---

    @classmethod
    def for_target(cls, target: str) -> "MCPClient":
        """Pick the client that can read `target`.

        `smithery:<qualified-name>` reads the server's advertised tools from
        the Smithery registry index — the one source available before the MCP
        transport is wired. Anything else is treated as a server URL and goes
        to the (still stubbed) MCP transport.

        A classmethod, not a static one, so that subclassing still works: a
        harness that swaps in its own client gets *its* class back for URL
        targets. An explicit `smithery:` target always selects the registry
        source, because naming a source is a decision, not a default.
        """
        if target.startswith(SMITHERY_PREFIX):
            return SmitheryRegistryClient(target[len(SMITHERY_PREFIX):].strip())
        return cls(target)

    @staticmethod
    def _to_tool(raw: dict[str, Any]) -> Tool:
        ann = raw.get("annotations")
        if not isinstance(ann, dict):
            ann = {}
        schema = raw.get("inputSchema")
        if not isinstance(schema, dict):
            schema = {}
        return Tool(
            name=_as_text(raw.get("name")),
            description=_as_text(raw.get("description")),
            read_only_hint=_as_optional_bool(ann.get("readOnlyHint")),
            destructive_hint=_as_optional_bool(ann.get("destructiveHint")),
            idempotent_hint=_as_optional_bool(ann.get("idempotentHint")),
            open_world_hint=_as_optional_bool(ann.get("openWorldHint")),
            input_schema=schema,
            raw=raw,
        )

    @staticmethod
    def _to_manifest(raw: dict[str, Any]) -> Manifest:
        def text_or_none(*keys: str) -> Optional[str]:
            for key in keys:
                value = raw.get(key)
                if value is not None:
                    return _as_text(value)
            return None

        return Manifest(
            present=True,
            origin=text_or_none("origin"),
            server_url=text_or_none("server_url", "serverUrl"),
            expires=text_or_none("expires"),
            capabilities_digest=text_or_none("capabilities_digest", "capabilitiesDigest"),
            signature_alg=text_or_none("signature_alg", "signatureAlg"),
            signature_verified=None,  # set by signature verification (not yet wired)
            raw=raw,
        )


class SmitheryRegistryClient(MCPClient):
    """Reads a server's advertised tools from the Smithery registry index.

    This is a **second-hand** source and the difference matters. It returns
    what the registry recorded when it last indexed the server, not what the
    server would answer *your* agent right now. It therefore cannot detect a
    server that serves clean descriptions to an indexer and poisoned ones to a
    live client, and it does not observe drift between index time and call
    time. Use it to vet a server before onboarding it, not to attest that a
    connection is safe.

    Two fields the index does not carry, declared honestly rather than
    inferred as empty:

    * ``annotations`` — stripped by this API (verified across 12,696 tool
      objects), so declared-vs-actual capability checks cannot run.
    * ``.well-known/mcp.json`` — never fetched, so manifest integrity is
      not merely absent, it is unchecked.
    """

    BASE = "https://registry.smithery.ai"
    supports_annotations = False
    supports_manifest = False

    def __init__(self, qualified_name: str, timeout: int = 20) -> None:
        super().__init__(f"{SMITHERY_PREFIX}{qualified_name}")
        if not qualified_name:
            raise ValueError(
                "no server name given — use 'smithery:<qualified-name>', "
                "e.g. smithery:exa"
            )
        self.qualified_name = qualified_name
        self.timeout = timeout

    @property
    def source_url(self) -> str:
        return f"{self.BASE}/servers/{quote(self.qualified_name, safe='@/')}"

    def _transport_list_tools(self) -> list[dict[str, Any]]:
        req = urllib.request.Request(self.source_url, headers={
            "Accept": "application/json",
            "User-Agent": f"mcpsurface/{__version__}",
        })
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                # Cap the read: the response is attacker-influenced content
                # from a third party, and an unbounded read is a DoS surface.
                payload = json.loads(r.read(MAX_RESPONSE_BYTES).decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code == 404:
                raise ValueError(
                    f"no server named {self.qualified_name!r} in the Smithery "
                    f"registry (404)"
                ) from e
            raise ValueError(f"registry returned HTTP {e.code}") from e
        except urllib.error.URLError as e:
            raise ValueError(f"could not reach the registry: {e.reason}") from e
        except json.JSONDecodeError as e:
            raise ValueError(f"registry returned malformed JSON: {e}") from e

        if isinstance(payload, dict) and payload.get("error") and "tools" not in payload:
            raise ValueError(f"registry error: {str(payload['error'])[:120]}")
        tools = payload.get("tools") if isinstance(payload, dict) else None
        return tools if isinstance(tools, list) else []

    def _transport_get_manifest(self) -> Optional[dict[str, Any]]:
        # Not "absent" — never looked. supports_manifest=False makes the
        # manifest detector report that distinction instead of asserting one.
        return None
