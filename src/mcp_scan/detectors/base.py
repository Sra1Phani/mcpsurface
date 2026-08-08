"""The extension point.

To add a check, subclass Detector, implement run(), and register it.
The runner discovers detectors via the registry; nothing else needs to
change. requires_llm gates a detector behind the --llm flag.
"""
from __future__ import annotations

from abc import ABC, abstractmethod

from ..models import Finding, ScanContext


class Detector(ABC):
    #: stable, namespaced id, e.g. "injection", "scope_class"
    id: str = ""
    #: human title for reports
    title: str = ""
    #: if True, only runs when an LLM judge is supplied (--llm)
    requires_llm: bool = False

    @abstractmethod
    def run(self, ctx: ScanContext) -> list[Finding]:
        """Inspect ctx and return zero or more findings. Must not mutate ctx."""
        raise NotImplementedError
