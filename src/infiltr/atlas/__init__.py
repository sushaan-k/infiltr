"""MITRE ATLAS mapping and report generation modules.

Public names are resolved lazily (PEP 562) so that importing a single
submodule -- e.g. :mod:`infiltr.atlas.baseline` from the CLI -- does not also
import the Jinja2-based report renderer and the taxonomy loader.
"""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from infiltr.atlas.baseline import (
        BaselineComparison,
        compare_findings,
        finding_fingerprint,
        parse_severity,
        severity_at_or_above,
    )
    from infiltr.atlas.mapper import ATLASMapper
    from infiltr.atlas.report import ATLASReport
    from infiltr.atlas.taxonomy import ATLASTaxonomy, Mitigation, Tactic, Technique

__all__ = [
    "ATLASMapper",
    "ATLASReport",
    "ATLASTaxonomy",
    "BaselineComparison",
    "Mitigation",
    "Tactic",
    "Technique",
    "compare_findings",
    "finding_fingerprint",
    "parse_severity",
    "severity_at_or_above",
]

_LAZY_EXPORTS: dict[str, str] = {
    "ATLASMapper": "infiltr.atlas.mapper",
    "ATLASReport": "infiltr.atlas.report",
    "ATLASTaxonomy": "infiltr.atlas.taxonomy",
    "BaselineComparison": "infiltr.atlas.baseline",
    "Mitigation": "infiltr.atlas.taxonomy",
    "Tactic": "infiltr.atlas.taxonomy",
    "Technique": "infiltr.atlas.taxonomy",
    "compare_findings": "infiltr.atlas.baseline",
    "finding_fingerprint": "infiltr.atlas.baseline",
    "parse_severity": "infiltr.atlas.baseline",
    "severity_at_or_above": "infiltr.atlas.baseline",
}


def __getattr__(name: str) -> object:
    """Resolve public exports lazily on first attribute access."""
    module_name = _LAZY_EXPORTS.get(name)
    if module_name is None:
        raise AttributeError(f"module 'infiltr.atlas' has no attribute '{name}'")
    value = getattr(importlib.import_module(module_name), name)
    globals()[name] = value  # cache so later lookups skip __getattr__
    return value


def __dir__() -> list[str]:
    """Expose the lazy exports to ``dir()`` and tab-completion."""
    return sorted([*globals().keys(), *__all__])
