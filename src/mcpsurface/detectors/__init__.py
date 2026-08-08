"""Detector registry.

To add a check: subclass Detector (see base.py), then add an instance to
REGISTRY below. The runner iterates this list; the CLI and JSON report
pick up its findings automatically. Detectors with requires_llm=True only
run when --llm is passed (the runner skips them otherwise).
"""
from __future__ import annotations

from .base import Detector
from .injection import InjectionDetector
from .manifest import ManifestDetector
from .scope_class import ScopeClassDetector

#: Ordered list of active detectors. Order only affects finding order.
REGISTRY: list[Detector] = [
    InjectionDetector(),
    ScopeClassDetector(),
    ManifestDetector(),
]

__all__ = ["REGISTRY", "Detector"]
