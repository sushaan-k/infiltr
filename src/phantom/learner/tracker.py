"""Success rate tracking over training iterations."""

from __future__ import annotations

from dataclasses import dataclass, field

from phantom.models import AttackCategory, OutcomeType, ProbeResult


@dataclass
class _CategoryStats:
    """Running counters for a single attack category."""

    successes: int = 0
    total: int = 0

    @property
    def rate(self) -> float:
        """Return the success rate, or 0.0 if no probes recorded."""
        if self.total == 0:
            return 0.0
        return self.successes / self.total


@dataclass
class SuccessTracker:
    """Track attack success rates per category over training iterations.

    Records every probe result and maintains per-category running
    statistics as well as snapshot history for learning-curve analysis.
    """

    _category_stats: dict[str, _CategoryStats] = field(default_factory=dict)
    _history: list[dict[str, float]] = field(default_factory=list)
    _iteration: int = 0
    snapshot_interval: int = 10

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def record(self, probe: ProbeResult) -> None:
        """Record a probe result and update running counters.

        Args:
            probe: The probe result to record.
        """
        cat = probe.category.value
        if cat not in self._category_stats:
            self._category_stats[cat] = _CategoryStats()

        stats = self._category_stats[cat]
        stats.total += 1

        if probe.outcome in (OutcomeType.FULL_BYPASS, OutcomeType.PARTIAL_BYPASS):
            stats.successes += 1

        self._iteration += 1

        if self._iteration % self.snapshot_interval == 0:
            self._take_snapshot()

    def success_rate(self, category: str | AttackCategory) -> float:
        """Return the cumulative success rate for a category.

        Args:
            category: Attack category name or enum value.

        Returns:
            Success rate between 0.0 and 1.0, or 0.0 if no probes.
        """
        key = category.value if isinstance(category, AttackCategory) else category
        stats = self._category_stats.get(key)
        if stats is None:
            return 0.0
        return stats.rate

    @property
    def history(self) -> list[dict[str, float]]:
        """Return the list of snapshots taken at each interval."""
        return list(self._history)

    @property
    def iteration(self) -> int:
        """Return the current iteration count."""
        return self._iteration

    def plot_learning_curve(self) -> dict[str, list[float]]:
        """Build data series suitable for plotting a learning curve.

        Returns a mapping from category name to a list of success-rate
        values, one per snapshot.  The ``"iteration"`` key holds the
        corresponding iteration numbers.

        Returns:
            Dictionary with ``"iteration"`` plus one key per category.
        """
        if not self._history:
            return {"iteration": []}

        all_cats: set[str] = set()
        for snap in self._history:
            all_cats.update(k for k in snap if k != "iteration")

        result: dict[str, list[float]] = {"iteration": []}
        for cat in sorted(all_cats):
            result[cat] = []

        for snap in self._history:
            result["iteration"].append(snap["iteration"])
            for cat in sorted(all_cats):
                result[cat].append(snap.get(cat, 0.0))

        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _take_snapshot(self) -> None:
        """Record current success rates for every tracked category."""
        snap: dict[str, float] = {"iteration": float(self._iteration)}
        for cat, stats in self._category_stats.items():
            snap[cat] = stats.rate
        self._history.append(snap)
