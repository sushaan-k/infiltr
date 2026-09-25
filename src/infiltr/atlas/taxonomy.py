"""MITRE ATLAS technique definitions and taxonomy loader."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from infiltr.exceptions import TaxonomyError
from infiltr.logging import get_logger
from infiltr.models import Severity

logger = get_logger("infiltr.atlas.taxonomy")

_DEFAULT_DATA_PATH = Path(__file__).parent / "data" / "techniques.json"


class Mitigation(BaseModel):
    """An ATLAS mitigation (e.g. ``AML.M0020 Generative AI Guardrails``)."""

    id: str | None = None
    name: str

    def __str__(self) -> str:
        return f"{self.id} {self.name}" if self.id else self.name


class Tactic(BaseModel):
    """An ATLAS tactic (e.g. ``AML.TA0005 Execution``)."""

    id: str
    name: str


class SubTechnique(BaseModel):
    """A sub-technique within a MITRE ATLAS technique."""

    id: str
    name: str
    description: str
    mitigations: list[Mitigation] = Field(default_factory=list)


class Technique(BaseModel):
    """A MITRE ATLAS technique with its associated metadata.

    ``tactics`` lists every ATLAS tactic the technique achieves, in upstream
    order; ``tactic`` is the first of them and is what findings report.
    ``remediation`` is infiltr's short defensive guidance, while
    ``mitigations`` are the official ATLAS mitigations.
    """

    id: str
    name: str
    tactic: str
    tactics: list[str] = Field(default_factory=list)
    description: str
    subtechniques: list[SubTechnique] = Field(default_factory=list)
    mitigations: list[Mitigation] = Field(default_factory=list)
    remediation: str = ""
    severity_default: Severity = Severity.MEDIUM
    references: list[str] = Field(default_factory=list)

    def get_subtechnique(self, sub_id: str) -> SubTechnique | None:
        """Look up a sub-technique by ID.

        Args:
            sub_id: The sub-technique ID (e.g., 'AML.T0051.001').

        Returns:
            The matching SubTechnique, or None.
        """
        for sub in self.subtechniques:
            if sub.id == sub_id:
                return sub
        return None


class CategoryMapping(BaseModel):
    """Mapping from an infiltr attack category to ATLAS technique IDs.

    Attributes:
        techniques: ATLAS IDs related to the category.
        description: Human-readable summary of the category.
        default: ID assigned to a successful probe when no override applies.
        by_strategy: Overrides keyed by attack strategy (``indirect``, or
            ``multi_turn`` for turns after the first of a conversation).
        on_info_leak: Override for probes whose outcome is an info leak.
    """

    techniques: list[str]
    description: str
    default: str
    by_strategy: dict[str, str] = Field(default_factory=dict)
    on_info_leak: str | None = None

    def referenced_ids(self) -> list[str]:
        """Return every technique ID this mapping can resolve to or lists."""
        ids = [*self.techniques, self.default, *self.by_strategy.values()]
        if self.on_info_leak:
            ids.append(self.on_info_leak)
        return list(dict.fromkeys(ids))


def _parse_mitigations(entries: list[Any]) -> list[Mitigation]:
    """Parse mitigations given as ``{"id", "name"}`` objects or plain strings."""
    return [
        Mitigation(name=entry) if isinstance(entry, str) else Mitigation(**entry)
        for entry in entries
    ]


class ATLASTaxonomy:
    """Loader and query interface for the MITRE ATLAS technique database.

    Loads technique definitions from a JSON file and provides
    lookup methods used by the ATLASMapper.

    Args:
        data_path: Path to the ATLAS techniques JSON file. Defaults
            to the packaged infiltr/atlas/data/techniques.json.
    """

    def __init__(self, data_path: Path | str | None = None) -> None:
        self._data_path = Path(data_path) if data_path else _DEFAULT_DATA_PATH
        self._techniques: dict[str, Technique] = {}
        self._category_map: dict[str, CategoryMapping] = {}
        self._tactics: list[Tactic] = []
        self._version = "unknown"
        self._loaded = False

    def load(self) -> None:
        """Load the ATLAS technique database from disk.

        Raises:
            TaxonomyError: If the data file is missing or malformed.
        """
        if not self._data_path.exists():
            raise TaxonomyError(f"Technique database not found at {self._data_path}")

        try:
            raw = json.loads(self._data_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            raise TaxonomyError(f"Failed to parse technique database: {exc}") from exc

        try:
            self._parse_techniques(raw)
            self._parse_categories(raw)
            self._tactics = [Tactic(**t) for t in raw.get("tactics", [])]
        except (KeyError, TypeError, ValueError) as exc:
            raise TaxonomyError(f"Malformed technique database: {exc}") from exc

        unresolved = sorted(
            tid
            for mapping in self._category_map.values()
            for tid in mapping.referenced_ids()
            if tid not in self._techniques
        )
        if unresolved:
            raise TaxonomyError(
                f"Attack categories reference unknown technique IDs: {unresolved}"
            )

        self._version = str(raw.get("version", "unknown"))
        if not self._tactics:
            names = dict.fromkeys(
                name for tech in self._techniques.values() for name in tech.tactics
            )
            self._tactics = [Tactic(id="", name=name) for name in names]
        self._loaded = True

        logger.info(
            "taxonomy_loaded",
            technique_count=len(self._techniques),
            category_count=len(self._category_map),
        )

    def _parse_techniques(self, raw: dict[str, Any]) -> None:
        """Parse technique entries from raw JSON data.

        Args:
            raw: The parsed JSON dictionary.
        """
        for entry in raw.get("techniques", []):
            # "tactic" (a single string) is accepted for pre-0.2 data files.
            tactics = entry.get("tactics") or [entry["tactic"]]
            technique = Technique(
                id=entry["id"],
                name=entry["name"],
                tactic=tactics[0],
                tactics=tactics,
                description=entry["description"],
                subtechniques=[
                    SubTechnique(
                        id=sub["id"],
                        name=sub["name"],
                        description=sub["description"],
                        mitigations=_parse_mitigations(sub.get("mitigations", [])),
                    )
                    for sub in entry.get("subtechniques", [])
                ],
                mitigations=_parse_mitigations(entry.get("mitigations", [])),
                remediation=entry.get("remediation", ""),
                severity_default=Severity(entry.get("severity_default", "MEDIUM")),
                references=entry.get("references", []),
            )
            self._techniques[technique.id] = technique

            for sub in technique.subtechniques:
                self._techniques[sub.id] = technique

    def _parse_categories(self, raw: dict[str, Any]) -> None:
        """Parse attack category mappings from raw JSON data.

        Args:
            raw: The parsed JSON dictionary.
        """
        for cat_name, cat_data in raw.get("attack_categories", {}).items():
            techniques = cat_data["techniques"]
            self._category_map[cat_name] = CategoryMapping(
                techniques=techniques,
                description=cat_data["description"],
                default=cat_data.get("default") or techniques[0],
                by_strategy=cat_data.get("by_strategy") or {},
                on_info_leak=cat_data.get("on_info_leak"),
            )

    def _ensure_loaded(self) -> None:
        """Load the taxonomy if it hasn't been loaded yet."""
        if not self._loaded:
            self.load()

    def get_technique(self, technique_id: str) -> Technique | None:
        """Look up a technique by its ID.

        Args:
            technique_id: The ATLAS technique ID (e.g., 'AML.T0051').

        Returns:
            The Technique if found, else None.
        """
        self._ensure_loaded()
        return self._techniques.get(technique_id)

    def get_display_name(self, technique_id: str) -> str | None:
        """Return the ATLAS display name for a technique or sub-technique.

        Sub-techniques are shown as ``"<technique>: <sub-technique>"``, the
        convention used on atlas.mitre.org (e.g. ``LLM Prompt Injection:
        Direct``).

        Args:
            technique_id: The ATLAS technique or sub-technique ID.

        Returns:
            The display name, or None if the ID is unknown.
        """
        technique = self.get_technique(technique_id)
        if technique is None:
            return None
        sub = technique.get_subtechnique(technique_id)
        return f"{technique.name}: {sub.name}" if sub else technique.name

    def get_category_mapping(self, category: str) -> CategoryMapping | None:
        """Return the technique mapping for an attack category.

        Args:
            category: The attack category name (e.g., 'prompt_injection').

        Returns:
            The CategoryMapping, or None if the category is unknown.
        """
        self._ensure_loaded()
        return self._category_map.get(category)

    def get_techniques_for_category(self, category: str) -> list[Technique]:
        """Get all techniques associated with an attack category.

        Args:
            category: The attack category name (e.g., 'prompt_injection').

        Returns:
            A list of Technique objects.
        """
        self._ensure_loaded()
        mapping = self._category_map.get(category)
        if not mapping:
            return []

        seen: set[str] = set()
        results: list[Technique] = []
        for tid in mapping.techniques:
            tech = self._techniques.get(tid)
            if tech and tech.id not in seen:
                seen.add(tech.id)
                results.append(tech)
        return results

    def get_default_severity(self, technique_id: str) -> Severity:
        """Get the default severity for a technique.

        Args:
            technique_id: The ATLAS technique ID.

        Returns:
            The default Severity, or MEDIUM if the technique is unknown.
        """
        self._ensure_loaded()
        technique = self._techniques.get(technique_id)
        if technique:
            return technique.severity_default
        return Severity.MEDIUM

    def get_mitigations(self, technique_id: str) -> list[Mitigation]:
        """Get the official ATLAS mitigations for a technique.

        For a sub-technique, the parent's mitigations come first, followed by
        any that ATLAS lists only for the sub-technique.

        Args:
            technique_id: The ATLAS technique or sub-technique ID.

        Returns:
            A list of Mitigation objects (empty if the ID is unknown).
        """
        self._ensure_loaded()
        technique = self._techniques.get(technique_id)
        if technique is None:
            return []
        mitigations = list(technique.mitigations)
        sub = technique.get_subtechnique(technique_id)
        if sub:
            seen = {str(m) for m in mitigations}
            mitigations += [m for m in sub.mitigations if str(m) not in seen]
        return mitigations

    def get_remediation(self, technique_id: str) -> str:
        """Get infiltr's defensive guidance for a technique.

        Args:
            technique_id: The ATLAS technique or sub-technique ID.

        Returns:
            The remediation text, or an empty string if none is defined.
        """
        self._ensure_loaded()
        technique = self._techniques.get(technique_id)
        return technique.remediation if technique else ""

    @property
    def version(self) -> str:
        """Return the MITRE ATLAS release the bundled data was taken from."""
        self._ensure_loaded()
        return self._version

    @property
    def tactics(self) -> list[Tactic]:
        """Return the tactics covered by the taxonomy, in ATLAS matrix order."""
        self._ensure_loaded()
        return list(self._tactics)

    @property
    def techniques(self) -> list[Technique]:
        """Return the top-level techniques (sub-techniques are nested)."""
        self._ensure_loaded()
        return list({t.id: t for t in self._techniques.values()}.values())

    @property
    def all_technique_ids(self) -> list[str]:
        """Return all loaded technique IDs."""
        self._ensure_loaded()
        return list(self._techniques.keys())

    @property
    def all_categories(self) -> list[str]:
        """Return all loaded attack category names."""
        self._ensure_loaded()
        return list(self._category_map.keys())
