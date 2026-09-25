"""Offline validation of the bundled ATLAS data file.

These checks catch malformed or dangling IDs without network access. Drift
against upstream MITRE ATLAS is checked separately by the maintainer script
``scripts/sync_atlas.py --check``.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

from infiltr.atlas.taxonomy import ATLASTaxonomy
from infiltr.models import AttackCategory, Severity

DATA_PATH = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "infiltr"
    / "atlas"
    / "data"
    / "techniques.json"
)

TECHNIQUE_ID = re.compile(r"^AML\.T\d{4}$")
SUBTECHNIQUE_ID = re.compile(r"^AML\.T\d{4}\.\d{3}$")
MITIGATION_ID = re.compile(r"^AML\.M\d{4}$")
TACTIC_ID = re.compile(r"^AML\.TA\d{4}$")
ATLAS_VERSION = re.compile(r"^\d{4}\.\d{2}(\.\d+)?$")


@pytest.fixture(scope="module")
def data() -> dict[str, Any]:
    return json.loads(DATA_PATH.read_text(encoding="utf-8"))


def _all_ids(data: dict[str, Any]) -> list[str]:
    ids = []
    for tech in data["techniques"]:
        ids.append(tech["id"])
        ids.extend(sub["id"] for sub in tech["subtechniques"])
    return ids


def test_source_version_recorded(data: dict[str, Any]) -> None:
    assert ATLAS_VERSION.match(data["version"])
    source = data["source"]
    assert source["atlas_version"] == data["version"]
    assert source["url"] == "https://github.com/mitre-atlas/atlas-data"
    assert source["format_version"]


def test_tactics_well_formed(data: dict[str, Any]) -> None:
    ids = [t["id"] for t in data["tactics"]]
    assert all(TACTIC_ID.match(i) for i in ids), ids
    assert len(ids) == len(set(ids))


def test_technique_ids_well_formed_and_unique(data: dict[str, Any]) -> None:
    for tech in data["techniques"]:
        assert TECHNIQUE_ID.match(tech["id"]), tech["id"]
        for sub in tech["subtechniques"]:
            assert SUBTECHNIQUE_ID.match(sub["id"]), sub["id"]
            assert sub["id"].startswith(tech["id"] + "."), sub["id"]
    ids = _all_ids(data)
    assert len(ids) == len(set(ids))


def test_techniques_complete(data: dict[str, Any]) -> None:
    tactic_names = {t["name"] for t in data["tactics"]}
    for tech in data["techniques"]:
        tid = tech["id"]
        assert tech["name"] and tech["description"], tid
        assert tech["tactics"], tid
        assert set(tech["tactics"]) <= tactic_names, tid
        assert tech["remediation"].strip(), f"{tid} has no remediation"
        Severity(tech["severity_default"])
        assert tech["references"] == [f"https://atlas.mitre.org/techniques/{tid}"]
        for sub in tech["subtechniques"]:
            assert sub["name"] and sub["description"], sub["id"]


def test_mitigation_ids_well_formed(data: dict[str, Any]) -> None:
    names: dict[str, str] = {}
    for tech in data["techniques"]:
        entries = list(tech["mitigations"])
        for sub in tech["subtechniques"]:
            entries.extend(sub["mitigations"])
        for mitigation in entries:
            assert MITIGATION_ID.match(mitigation["id"]), mitigation
            assert mitigation["name"]
            # The same mitigation ID must always carry the same name.
            assert (
                names.setdefault(mitigation["id"], mitigation["name"])
                == (mitigation["name"])
            )


def test_every_attack_category_mapped(data: dict[str, Any]) -> None:
    assert set(data["attack_categories"]) == {c.value for c in AttackCategory}


def test_category_mappings_resolve(data: dict[str, Any]) -> None:
    known = set(_all_ids(data))
    for name, mapping in data["attack_categories"].items():
        referenced = [
            *mapping["techniques"],
            mapping["default"],
            *mapping["by_strategy"].values(),
        ]
        if mapping.get("on_info_leak"):
            referenced.append(mapping["on_info_leak"])
        missing = [tid for tid in referenced if tid not in known]
        assert not missing, f"{name} references unknown IDs {missing}"
        # Every ID a probe can resolve to is listed under the category.
        resolvable = set(referenced) - set(mapping["techniques"])
        assert not resolvable, f"{name} does not list {sorted(resolvable)}"
        assert set(mapping["by_strategy"]) <= {"direct", "indirect", "multi_turn"}


def test_bundled_data_loads(data: dict[str, Any]) -> None:
    taxonomy = ATLASTaxonomy(DATA_PATH)
    taxonomy.load()
    assert sorted(taxonomy.all_technique_ids) == sorted(_all_ids(data))
    assert taxonomy.version == data["version"]
