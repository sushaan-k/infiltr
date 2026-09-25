"""infiltr: RL-based adversarial red-team agent for LLM systems.

infiltr uses reinforcement learning to discover novel attack strategies
against LLM applications. It maps discovered vulnerabilities to the
MITRE ATLAS framework and produces compliance-ready reports.

Example:
    >>> from infiltr import RedTeam, Target, ATLASReport
    >>> target = Target(endpoint="https://api.example.com/chat")
    >>> red_team = RedTeam(target=target)
    >>> results = await red_team.run()
    >>> report = ATLASReport(results)
    >>> report.to_json("results.json")

The public symbols are imported lazily (PEP 562 ``__getattr__``) so that
merely importing :mod:`infiltr` -- for example when Typer imports the CLI
module for ``infiltr --help`` -- does not eagerly pull in the RL stack
(``torch``, ``numpy``).  Attribute access such as ``infiltr.RedTeam``
triggers the underlying import on demand; ``infiltr.__version__`` likewise
reads the package metadata on first access.
"""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from infiltr.atlas.report import ATLASReport
    from infiltr.redteam import RedTeam, RedTeamConfig, RedTeamResults
    from infiltr.target import Target, TargetConfig

    __version__: str

__all__ = [
    "ATLASReport",
    "RedTeam",
    "RedTeamConfig",
    "RedTeamResults",
    "Target",
    "TargetConfig",
]

# Map each public name to the submodule that defines it, so the heavy
# submodules (and their ``torch`` dependency) are only imported when the
# symbol is actually accessed.
_LAZY_EXPORTS: dict[str, str] = {
    "ATLASReport": "infiltr.atlas.report",
    "RedTeam": "infiltr.redteam",
    "RedTeamConfig": "infiltr.redteam",
    "RedTeamResults": "infiltr.redteam",
    "Target": "infiltr.target",
    "TargetConfig": "infiltr.target",
}


def _read_version() -> str:
    """Return the installed distribution version.

    ``importlib.metadata`` costs tens of milliseconds to import and scan, so
    it only runs when ``infiltr.__version__`` is first read.
    """
    from importlib.metadata import PackageNotFoundError, version

    try:
        return version("infiltr")
    except PackageNotFoundError:  # pragma: no cover - running from a source tree
        return "0+unknown"


def __getattr__(name: str) -> object:
    """Resolve public exports (and ``__version__``) lazily on first access."""
    if name == "__version__":
        value: object = _read_version()
        globals()[name] = value
        return value
    module_name = _LAZY_EXPORTS.get(name)
    if module_name is None:
        raise AttributeError(f"module 'infiltr' has no attribute '{name}'")
    value = getattr(importlib.import_module(module_name), name)
    globals()[name] = value  # cache so later lookups skip __getattr__
    return value


def __dir__() -> list[str]:
    """Expose the lazy exports to ``dir()`` and tab-completion."""
    return sorted({*globals().keys(), *__all__, "__version__"})
