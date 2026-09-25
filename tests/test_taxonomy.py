"""Tests for the ATLAS taxonomy module."""

from __future__ import annotations

import json

import pytest

from infiltr.atlas.taxonomy import ATLASTaxonomy
from infiltr.exceptions import TaxonomyError
from infiltr.models import Severity


class TestATLASTaxonomy:
    """Tests for ATLASTaxonomy loading and querying."""

    def test_load_default(self, taxonomy: ATLASTaxonomy) -> None:
        assert len(taxonomy.all_technique_ids) > 0
        assert len(taxonomy.all_categories) > 0

    def test_get_technique_by_id(self, taxonomy: ATLASTaxonomy) -> None:
        tech = taxonomy.get_technique("AML.T0051")
        assert tech is not None
        assert tech.name == "LLM Prompt Injection"
        assert tech.tactic == "Execution"
        assert tech.tactics == ["Execution"]

    def test_multi_tactic_technique(self, taxonomy: ATLASTaxonomy) -> None:
        tech = taxonomy.get_technique("AML.T0054")
        assert tech is not None
        assert tech.tactics == ["Defense Evasion", "Privilege Escalation"]
        assert tech.tactic == "Defense Evasion"

    def test_get_subtechnique(self, taxonomy: ATLASTaxonomy) -> None:
        tech = taxonomy.get_technique("AML.T0051.001")
        assert tech is not None
        sub = tech.get_subtechnique("AML.T0051.001")
        assert sub is not None
        assert sub.name == "Indirect"
        assert (
            taxonomy.get_display_name("AML.T0051.001")
            == "LLM Prompt Injection: Indirect"
        )
        assert taxonomy.get_display_name("AML.T0057") == "LLM Data Leakage"
        assert taxonomy.get_display_name("AML.T9999") is None

    def test_get_nonexistent_technique(self, taxonomy: ATLASTaxonomy) -> None:
        assert taxonomy.get_technique("AML.T9999") is None

    def test_get_techniques_for_category(self, taxonomy: ATLASTaxonomy) -> None:
        techs = taxonomy.get_techniques_for_category("prompt_injection")
        assert len(techs) > 0
        assert any(t.id == "AML.T0051" for t in techs)

    def test_get_techniques_for_unknown_category(self, taxonomy: ATLASTaxonomy) -> None:
        assert taxonomy.get_techniques_for_category("nonexistent") == []

    def test_get_default_severity(self, taxonomy: ATLASTaxonomy) -> None:
        assert taxonomy.get_default_severity("AML.T0054") == Severity.CRITICAL
        assert taxonomy.get_default_severity("AML.T0051") == Severity.HIGH
        assert taxonomy.get_default_severity("AML.T9999") == Severity.MEDIUM

    def test_get_mitigations(self, taxonomy: ATLASTaxonomy) -> None:
        mitigations = taxonomy.get_mitigations("AML.T0051")
        ids = [m.id for m in mitigations]
        assert "AML.M0020" in ids
        assert "AML.M0020 Generative AI Guardrails" in [str(m) for m in mitigations]
        assert taxonomy.get_mitigations("AML.T9999") == []

    def test_subtechnique_mitigations_include_parent(
        self, taxonomy: ATLASTaxonomy
    ) -> None:
        parent_ids = [m.id for m in taxonomy.get_mitigations("AML.T0034")]
        sub_ids = [m.id for m in taxonomy.get_mitigations("AML.T0034.001")]
        assert sub_ids[: len(parent_ids)] == parent_ids
        assert len(sub_ids) == len(set(sub_ids))

    def test_get_remediation(self, taxonomy: ATLASTaxonomy) -> None:
        assert taxonomy.get_remediation("AML.T0051.000")
        assert taxonomy.get_remediation("AML.T9999") == ""

    def test_version_and_tactics(self, taxonomy: ATLASTaxonomy) -> None:
        assert taxonomy.version != "unknown"
        names = [t.name for t in taxonomy.tactics]
        assert names.index("Initial Access") < names.index("Impact")

    def test_category_mapping(self, taxonomy: ATLASTaxonomy) -> None:
        mapping = taxonomy.get_category_mapping("prompt_injection")
        assert mapping is not None
        assert mapping.default == "AML.T0051.000"
        assert mapping.by_strategy["indirect"] == "AML.T0051.001"
        assert taxonomy.get_category_mapping("nonexistent") is None

    def test_unresolved_category_id_rejected(self, tmp_path) -> None:
        data = {
            "techniques": [
                {
                    "id": "AML.T0051",
                    "name": "LLM Prompt Injection",
                    "tactics": ["Execution"],
                    "description": "d",
                }
            ],
            "attack_categories": {
                "prompt_injection": {
                    "techniques": ["AML.T0051", "AML.T0054.000"],
                    "description": "d",
                }
            },
        }
        path = tmp_path / "t.json"
        path.write_text(json.dumps(data))
        with pytest.raises(TaxonomyError, match=r"AML\.T0054\.000"):
            ATLASTaxonomy(data_path=path).load()

    def test_legacy_format_still_loads(self, tmp_path) -> None:
        data = {
            "techniques": [
                {
                    "id": "AML.T0051",
                    "name": "LLM Prompt Injection",
                    "tactic": "Execution",
                    "description": "d",
                    "mitigations": ["Input validation"],
                }
            ],
            "attack_categories": {
                "prompt_injection": {"techniques": ["AML.T0051"], "description": "d"}
            },
        }
        path = tmp_path / "legacy.json"
        path.write_text(json.dumps(data))
        t = ATLASTaxonomy(data_path=path)
        assert t.get_technique("AML.T0051").tactics == ["Execution"]
        assert [str(m) for m in t.get_mitigations("AML.T0051")] == ["Input validation"]
        assert t.get_category_mapping("prompt_injection").default == "AML.T0051"
        assert [x.name for x in t.tactics] == ["Execution"]

    def test_missing_data_file(self) -> None:
        t = ATLASTaxonomy(data_path="/nonexistent/path.json")
        with pytest.raises(TaxonomyError, match="not found"):
            t.load()

    def test_all_categories(self, taxonomy: ATLASTaxonomy) -> None:
        cats = taxonomy.all_categories
        assert "prompt_injection" in cats
        assert "goal_hijacking" in cats
        assert "data_exfiltration" in cats
        assert "denial_of_service" in cats

    def test_auto_load_on_query(self) -> None:
        t = ATLASTaxonomy()
        tech = t.get_technique("AML.T0051")
        assert tech is not None
