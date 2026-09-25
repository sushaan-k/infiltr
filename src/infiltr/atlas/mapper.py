"""ATLAS technique mapper -- maps probe results to MITRE ATLAS findings."""

from __future__ import annotations

from infiltr.atlas.taxonomy import ATLASTaxonomy
from infiltr.logging import get_logger
from infiltr.models import (
    Finding,
    OutcomeType,
    ProbeResult,
    Severity,
)

logger = get_logger("infiltr.atlas.mapper")

_SEVERITY_RANK = {severity: idx for idx, severity in enumerate(Severity)}

# Used only when a probe's category has no mapping in the taxonomy.
_FALLBACK_TECHNIQUE_ID = "AML.T0051"


class ATLASMapper:
    """Maps attack probe results to MITRE ATLAS technique findings.

    Analyzes successful probes, determines the most specific ATLAS
    technique ID, assigns severity, and generates remediation advice.

    Args:
        taxonomy: An ATLASTaxonomy instance for technique lookups.
            If None, a default taxonomy will be loaded.
    """

    def __init__(self, taxonomy: ATLASTaxonomy | None = None) -> None:
        self._taxonomy = taxonomy or ATLASTaxonomy()

    def map_probe(self, probe: ProbeResult) -> Finding | None:
        """Map a single probe result to an ATLAS finding.

        Only probes with a successful outcome (full_bypass, partial_bypass,
        or info_leak) generate findings.

        Args:
            probe: The probe result to evaluate.

        Returns:
            A Finding if the probe was successful, else None.
        """
        if probe.outcome == OutcomeType.CLEAN_REFUSAL:
            return None
        if probe.outcome == OutcomeType.ERROR:
            return None

        technique_id = self._resolve_technique_id(probe)
        technique = self._taxonomy.get_technique(technique_id)

        if technique is None:
            technique_name = f"Unknown ({technique_id})"
            tactic = "Unknown"
        else:
            technique_name = (
                self._taxonomy.get_display_name(technique_id) or technique.name
            )
            tactic = technique.tactic

        severity = self._determine_severity(probe, technique_id)
        remediation = self._get_remediation(technique_id)

        finding = Finding(
            technique_id=technique_id,
            technique_name=technique_name,
            tactic=tactic,
            severity=severity,
            attack_prompt=probe.attack_prompt,
            response=probe.response,
            reproducibility=0.0,
            remediation=remediation,
            evidence=[],
            category=probe.category,
            probe_ids=[probe.probe_id],
        )

        logger.info(
            "finding_mapped",
            technique=technique_id,
            severity=severity.value,
            outcome=probe.outcome.value,
        )

        return finding

    def map_probes(self, probes: list[ProbeResult]) -> list[Finding]:
        """Map a batch of probe results to ATLAS findings.

        Deduplicates findings by technique ID and computes
        reproducibility rates from repeated successful probes.

        Args:
            probes: List of probe results from a red-team run.

        Returns:
            Deduplicated list of findings with reproducibility scores.
        """
        raw_findings: dict[str, list[Finding]] = {}

        for probe in probes:
            finding = self.map_probe(probe)
            if finding is None:
                continue

            key = f"{finding.technique_id}:{finding.category.value}"
            if key not in raw_findings:
                raw_findings[key] = []
            raw_findings[key].append(finding)

        deduplicated: list[Finding] = []
        total_probes_by_category: dict[str, int] = {}

        for probe in probes:
            cat_key = probe.category.value
            total_probes_by_category[cat_key] = (
                total_probes_by_category.get(cat_key, 0) + 1
            )

        for _key, findings in raw_findings.items():
            best = min(findings, key=lambda f: _SEVERITY_RANK[f.severity])
            cat_key = best.category.value
            total = total_probes_by_category.get(cat_key, 1)
            best.reproducibility = round(len(findings) / max(total, 1), 3)
            best.probe_ids = [f.probe_ids[0] for f in findings]
            deduplicated.append(best)

        deduplicated.sort(key=lambda f: _SEVERITY_RANK[f.severity])

        logger.info(
            "probes_mapped",
            total_probes=len(probes),
            findings_generated=len(deduplicated),
        )

        return deduplicated

    def _resolve_technique_id(self, probe: ProbeResult) -> str:
        """Determine the most specific ATLAS technique ID for a probe.

        An explicit ``probe.technique_id`` wins. Otherwise the category's
        mapping in the taxonomy decides, in order: the info-leak override,
        the strategy override (``multi_turn`` for turns after the first of a
        conversation, else ``probe.metadata["strategy"]``), then the default.

        Args:
            probe: The probe result.

        Returns:
            The technique ID string.
        """
        if probe.technique_id:
            return probe.technique_id

        mapping = self._taxonomy.get_category_mapping(probe.category.value)
        if mapping is None:
            return _FALLBACK_TECHNIQUE_ID

        if probe.outcome == OutcomeType.INFO_LEAK and mapping.on_info_leak:
            return mapping.on_info_leak

        if probe.conversation_id and probe.turn_number > 1:
            strategy: object = "multi_turn"
        else:
            strategy = probe.metadata.get("strategy")
        if isinstance(strategy, str) and strategy in mapping.by_strategy:
            return mapping.by_strategy[strategy]

        return mapping.default

    def _determine_severity(self, probe: ProbeResult, technique_id: str) -> Severity:
        """Determine the severity of a finding based on outcome and technique.

        Args:
            probe: The probe result.
            technique_id: The resolved ATLAS technique ID.

        Returns:
            The determined severity level.
        """
        base_severity = self._taxonomy.get_default_severity(technique_id)

        if probe.outcome == OutcomeType.FULL_BYPASS:
            severity_order = list(Severity)
            idx = severity_order.index(base_severity)
            return severity_order[max(0, idx - 1)]

        if probe.outcome == OutcomeType.INFO_LEAK:
            severity_order = list(Severity)
            idx = severity_order.index(base_severity)
            return severity_order[min(len(severity_order) - 1, idx + 1)]

        return base_severity

    def _get_remediation(self, technique_id: str) -> str:
        """Build remediation advice for a technique.

        Combines infiltr's defensive guidance for the technique with the
        official ATLAS mitigations (by ID and name) that apply to it.

        Args:
            technique_id: The ATLAS technique or sub-technique ID.

        Returns:
            A remediation string.
        """
        parts: list[str] = []
        guidance = self._taxonomy.get_remediation(technique_id)
        if guidance:
            parts.append(guidance)

        mitigations = self._taxonomy.get_mitigations(technique_id)
        if mitigations:
            parts.append(
                "ATLAS mitigations: " + "; ".join(str(m) for m in mitigations) + "."
            )

        if parts:
            return " ".join(parts)
        return (
            f"Review the MITRE ATLAS entry for {technique_id} "
            "(https://atlas.mitre.org) and apply its recommended mitigations."
        )
