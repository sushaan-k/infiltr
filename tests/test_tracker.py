"""Tests for the success rate tracker."""

from __future__ import annotations

import pytest

from phantom.learner.tracker import SuccessTracker
from phantom.models import AttackCategory, OutcomeType, ProbeResult


def _make_probe(
    category: AttackCategory = AttackCategory.PROMPT_INJECTION,
    outcome: OutcomeType = OutcomeType.FULL_BYPASS,
) -> ProbeResult:
    return ProbeResult(
        attack_prompt="test",
        response="test",
        outcome=outcome,
        reward=1.0 if outcome == OutcomeType.FULL_BYPASS else 0.0,
        category=category,
    )


class TestSuccessTracker:
    """Tests for SuccessTracker."""

    @pytest.fixture
    def tracker(self) -> SuccessTracker:
        return SuccessTracker(snapshot_interval=5)

    def test_empty_tracker_returns_zero(self, tracker: SuccessTracker) -> None:
        assert tracker.success_rate("prompt_injection") == 0.0
        assert tracker.iteration == 0

    def test_record_updates_rate(self, tracker: SuccessTracker) -> None:
        tracker.record(_make_probe(outcome=OutcomeType.FULL_BYPASS))
        tracker.record(_make_probe(outcome=OutcomeType.CLEAN_REFUSAL))
        assert tracker.success_rate(AttackCategory.PROMPT_INJECTION) == 0.5

    def test_record_multiple_categories(self, tracker: SuccessTracker) -> None:
        tracker.record(
            _make_probe(AttackCategory.PROMPT_INJECTION, OutcomeType.FULL_BYPASS)
        )
        tracker.record(
            _make_probe(AttackCategory.DATA_EXFILTRATION, OutcomeType.CLEAN_REFUSAL)
        )
        assert tracker.success_rate(AttackCategory.PROMPT_INJECTION) == 1.0
        assert tracker.success_rate(AttackCategory.DATA_EXFILTRATION) == 0.0

    def test_partial_bypass_counts_as_success(self, tracker: SuccessTracker) -> None:
        tracker.record(_make_probe(outcome=OutcomeType.PARTIAL_BYPASS))
        assert tracker.success_rate(AttackCategory.PROMPT_INJECTION) == 1.0

    def test_snapshots_taken_at_interval(self, tracker: SuccessTracker) -> None:
        for _ in range(5):
            tracker.record(_make_probe(outcome=OutcomeType.FULL_BYPASS))
        assert len(tracker.history) == 1
        assert tracker.history[0]["iteration"] == 5.0

    def test_plot_learning_curve_empty(self, tracker: SuccessTracker) -> None:
        curve = tracker.plot_learning_curve()
        assert curve == {"iteration": []}

    def test_plot_learning_curve_with_data(self, tracker: SuccessTracker) -> None:
        for i in range(10):
            outcome = (
                OutcomeType.FULL_BYPASS
                if i % 2 == 0
                else OutcomeType.CLEAN_REFUSAL
            )
            tracker.record(_make_probe(outcome=outcome))
        curve = tracker.plot_learning_curve()
        assert "iteration" in curve
        assert len(curve["iteration"]) == 2
        assert "prompt_injection" in curve

    def test_iteration_counter(self, tracker: SuccessTracker) -> None:
        for _ in range(7):
            tracker.record(_make_probe())
        assert tracker.iteration == 7

    def test_unknown_category_returns_zero(self, tracker: SuccessTracker) -> None:
        assert tracker.success_rate("nonexistent") == 0.0

    def test_success_rate_accepts_string(self, tracker: SuccessTracker) -> None:
        tracker.record(_make_probe(outcome=OutcomeType.FULL_BYPASS))
        assert tracker.success_rate("prompt_injection") == 1.0
