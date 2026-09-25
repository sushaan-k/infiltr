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
"""

from importlib.metadata import PackageNotFoundError, version

from infiltr.atlas.report import ATLASReport
from infiltr.redteam import RedTeam, RedTeamConfig, RedTeamResults
from infiltr.target import Target, TargetConfig

__all__ = [
    "ATLASReport",
    "RedTeam",
    "RedTeamConfig",
    "RedTeamResults",
    "Target",
    "TargetConfig",
]

try:
    __version__ = version("infiltr")
except PackageNotFoundError:  # pragma: no cover - running from a source tree
    __version__ = "0+unknown"
