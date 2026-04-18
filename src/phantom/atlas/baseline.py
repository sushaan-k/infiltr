"""Baseline comparison helpers for ATLAS findings."""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass

from phantom.models import Finding, Severity

_SEVERITY_ORDER: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}
_WHITESPACE_RE = re.compile(r"\s+")


@dataclass(frozen=True)
class BaselineComparison:
    """Result of comparing current findings against a prior baseline."""

    current_count: int
    baseline_count: int
    unchanged_count: int
    resolved_count: int
    new_findings: list[Finding]

    @property
    def new_count(self) -> int:
        """Return the number of findings not present in the baseline."""
        return len(self.new_findings)

    @property
    def new_by_severity(self) -> dict[str, int]:
        """Return new finding counts grouped by severity."""
        return {
            severity.value: sum(
                1 for finding in self.new_findings if finding.severity == severity
            )
            for severity in Severity
        }

    def has_new_at_or_above(self, threshold: Severity) -> bool:
        """Return whether any new finding meets or exceeds a severity threshold."""
        threshold_rank = _SEVERITY_ORDER[threshold]
        return any(
            _SEVERITY_ORDER[finding.severity] >= threshold_rank
            for finding in self.new_findings
        )

    def to_summary(self) -> dict[str, int | dict[str, int]]:
        """Return a JSON-serializable summary for report metadata."""
        return {
            "current_findings": self.current_count,
            "baseline_findings": self.baseline_count,
            "unchanged_findings": self.unchanged_count,
            "resolved_findings": self.resolved_count,
            "new_findings": self.new_count,
            "new_by_severity": self.new_by_severity,
        }


def parse_severity(value: str) -> Severity:
    """Parse a severity name for CLI threshold options."""
    try:
        return Severity(value.strip().upper())
    except ValueError as exc:
        valid = ", ".join(severity.value for severity in Severity)
        raise ValueError(f"Unknown severity '{value}'. Valid: {valid}") from exc


def severity_at_or_above(severity: Severity, threshold: Severity) -> bool:
    """Return whether ``severity`` meets or exceeds ``threshold``."""
    return _SEVERITY_ORDER[severity] >= _SEVERITY_ORDER[threshold]


def finding_fingerprint(finding: Finding) -> str:
    """Return a stable fingerprint for baseline comparisons.

    The fingerprint intentionally excludes target responses and timestamps so
    reruns can match the same vulnerability without storing sensitive output.
    """
    payload = {
        "technique_id": finding.technique_id,
        "category": finding.category.value,
        "severity": finding.severity.value,
        "attack_prompt": _normalize_text(finding.attack_prompt),
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def compare_findings(
    current: Iterable[Finding],
    baseline: Iterable[Finding],
) -> BaselineComparison:
    """Compare current findings against a baseline, preserving duplicates."""
    current_findings = list(current)
    baseline_findings = list(baseline)
    remaining = Counter(finding_fingerprint(finding) for finding in baseline_findings)

    unchanged_count = 0
    new_findings: list[Finding] = []
    for finding in current_findings:
        fingerprint = finding_fingerprint(finding)
        if remaining[fingerprint] > 0:
            remaining[fingerprint] -= 1
            unchanged_count += 1
        else:
            new_findings.append(finding)

    return BaselineComparison(
        current_count=len(current_findings),
        baseline_count=len(baseline_findings),
        unchanged_count=unchanged_count,
        resolved_count=sum(remaining.values()),
        new_findings=new_findings,
    )


def _normalize_text(value: str) -> str:
    """Normalize attacker-controlled text before fingerprinting."""
    return _WHITESPACE_RE.sub(" ", value.strip()).casefold()
