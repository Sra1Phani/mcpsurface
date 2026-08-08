"""mcpsurface — static trust audit for MCP servers.

Point it at an MCP server and get back a report on the things gateways
skip: tool-description poisoning, declared-vs-actual capability mismatch,
and manifest integrity. Heuristic, offline, deterministic, dependency-free.
"""
from __future__ import annotations

__version__ = "0.2.1"
