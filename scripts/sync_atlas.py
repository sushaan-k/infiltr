#!/usr/bin/env python3
"""Re-sync or validate infiltr's bundled ATLAS taxonomy against upstream MITRE ATLAS.

This is a maintainer tool. It is not run in CI and is not a runtime
dependency of infiltr (it needs PyYAML: ``pip install pyyaml``).

infiltr ships a curated subset of MITRE ATLAS in
``src/infiltr/atlas/data/techniques.json``. That file mixes two kinds of data:

* **Official ATLAS fields**, owned by this script: technique and sub-technique
  names, tactics, descriptions (first paragraph of the official text),
  mitigation IDs/names, reference URLs, the tactic list, and the
  ``version``/``source`` block.
* **infiltr fields**, owned by humans and preserved untouched: which IDs are
  included, ``severity_default``, ``remediation``, and ``attack_categories``.

To add a technique, append a stub such as
``{"id": "AML.T0070", "severity_default": "HIGH", "remediation": "..."}``
(with optional ``"subtechniques": [{"id": "AML.T0070.000"}]``) and run this
script without ``--check`` to fill in the official fields.

Usage::

    python scripts/sync_atlas.py --check          # exit 1 if the JSON drifted
    python scripts/sync_atlas.py                  # rewrite official fields
    python scripts/sync_atlas.py --source ATLAS-latest.yaml --check

``--source`` accepts a local path or URL to an ATLAS v6-format YAML export
(default: ``dist/ATLAS-latest.yaml`` on the atlas-data main branch).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
from pathlib import Path
from typing import Any

DEFAULT_SOURCE = (
    "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/"
    "dist/ATLAS-latest.yaml"
)
REPO_URL = "https://github.com/mitre-atlas/atlas-data"
TECHNIQUES_JSON = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "infiltr"
    / "atlas"
    / "data"
    / "techniques.json"
)

_MD_LINK = re.compile(r"\[([^\]]+)\]\(([^)]*)\)")
_CITATION = re.compile(r"\s*\[\[[^\]]+\]\]")


def load_upstream(source: str) -> dict[str, Any]:
    """Load an ATLAS YAML export from a path or URL."""
    try:
        import yaml
    except ImportError:
        sys.exit("PyYAML is required: pip install pyyaml")

    text = _read(source)
    # dist/ATLAS-latest.yaml is a git symlink; raw.githubusercontent.com serves
    # the link target ("v6/ATLAS-latest.yaml") as the body. Follow such links.
    for _ in range(3):
        target = text.strip()
        if "\n" in target or not target.endswith(".yaml"):
            break
        source = source.rsplit("/", 1)[0] + "/" + target
        text = _read(source)

    data: dict[str, Any] = yaml.safe_load(text)
    fmt = str(data.get("format-version", ""))
    if not fmt.startswith("6."):
        sys.exit(f"Unsupported ATLAS format-version {fmt!r}; expected 6.x")
    return data


def _read(source: str) -> str:
    if re.match(r"https?://", source):
        with urllib.request.urlopen(source, timeout=60) as resp:  # noqa: S310
            return str(resp.read().decode("utf-8"))
    return Path(source).read_text(encoding="utf-8")


def clean_description(text: str) -> str:
    """Return the first paragraph of an ATLAS description as plain text."""
    paragraphs = [p for p in text.strip().split("\n\n") if p.strip()]
    first = paragraphs[0] if paragraphs else ""
    first = _MD_LINK.sub(r"\1", first)
    first = _CITATION.sub("", first)
    return " ".join(first.split())


class Upstream:
    """Indexed view over an ATLAS v6 export."""

    def __init__(self, data: dict[str, Any], source: str) -> None:
        self.data = data
        self.source = source
        self.techniques: dict[str, Any] = data["techniques"]
        self.tactics: dict[str, Any] = data["tactics"]
        self.mitigations: dict[str, Any] = data["mitigations"]
        rels: dict[str, Any] = data["relationships"]

        positions = {
            seq["target"]: seq["position"]
            for seq in rels.get(data["matrix"]["id"], {}).get("sequences", [])
        }
        self.tactic_order = sorted(self.tactics, key=lambda t: positions.get(t, 999))

        self.achieves: dict[str, list[str]] = {}
        self.parent: dict[str, str] = {}
        self.mitigated_by: dict[str, list[str]] = {}
        for source_id, kinds in rels.items():
            for rel in kinds.get("achieves", []):
                self.achieves.setdefault(source_id, []).append(rel["target"])
            for rel in kinds.get("specializes", []):
                self.parent[source_id] = rel["target"]
            for rel in kinds.get("mitigates", []):
                self.mitigated_by.setdefault(rel["target"], []).append(source_id)

    def tactic_ids(self, technique_id: str) -> list[str]:
        # Upstream order (the first tactic is what infiltr reports on a finding).
        return list(self.achieves.get(technique_id, []))

    def mitigation_list(self, technique_id: str) -> list[dict[str, str]]:
        ids = sorted(set(self.mitigated_by.get(technique_id, [])))
        return [{"id": m, "name": self.mitigations[m]["name"]} for m in ids]

    @property
    def version(self) -> str:
        return str(self.data["collection"]["version"])


def build(current: dict[str, Any], up: Upstream) -> tuple[dict[str, Any], list[str]]:
    """Return the JSON with official fields refreshed, plus a list of errors."""
    errors: list[str] = []
    used_tactics: set[str] = set()
    techniques: list[dict[str, Any]] = []

    for entry in current.get("techniques", []):
        tid = entry["id"]
        official = up.techniques.get(tid)
        if official is None:
            errors.append(f"{tid}: not found in upstream ATLAS {up.version}")
            techniques.append(entry)
            continue
        if tid in up.parent:
            errors.append(f"{tid}: is a sub-technique upstream, not a technique")

        tactic_ids = up.tactic_ids(tid)
        used_tactics.update(tactic_ids)

        subs: list[dict[str, Any]] = []
        for sub in entry.get("subtechniques", []):
            sid = sub["id"]
            sub_official = up.techniques.get(sid)
            if sub_official is None:
                errors.append(f"{sid}: not found in upstream ATLAS {up.version}")
                subs.append(sub)
                continue
            if up.parent.get(sid) != tid:
                errors.append(
                    f"{sid}: upstream parent is {up.parent.get(sid)}, not {tid}"
                )
            subs.append(
                {
                    "id": sid,
                    "name": sub_official["name"],
                    "description": clean_description(sub_official["description"]),
                    "mitigations": up.mitigation_list(sid),
                }
            )

        techniques.append(
            {
                "id": tid,
                "name": official["name"],
                "tactics": [up.tactics[t]["name"] for t in tactic_ids],
                "description": clean_description(official["description"]),
                "subtechniques": subs,
                "mitigations": up.mitigation_list(tid),
                "remediation": entry.get("remediation", ""),
                "severity_default": entry.get("severity_default", "MEDIUM"),
                "references": [f"https://atlas.mitre.org/techniques/{tid}"],
            }
        )

    release_date = str(up.data["collection"].get("modified-date", ""))
    result = {
        "version": up.version,
        "source": {
            "name": "MITRE ATLAS",
            "url": REPO_URL,
            "file": f"dist/v6/ATLAS-{up.version}.yaml",
            "atlas_version": up.version,
            "format_version": str(up.data["format-version"]),
            "release_date": release_date,
            "note": (
                "Curated subset relevant to LLM applications and agents. "
                "Descriptions are the first paragraph of the official text. "
                "Re-sync with scripts/sync_atlas.py."
            ),
        },
        "tactics": [
            {"id": t, "name": up.tactics[t]["name"]}
            for t in up.tactic_order
            if t in used_tactics
        ],
        "techniques": techniques,
        "attack_categories": current.get("attack_categories", {}),
    }
    return result, errors


def diff(old: Any, new: Any, path: str = "") -> list[str]:
    """Return human-readable differences between two JSON values."""
    if isinstance(old, dict) and isinstance(new, dict):
        out: list[str] = []
        for key in sorted(set(old) | set(new)):
            out += diff(old.get(key), new.get(key), f"{path}.{key}" if path else key)
        return out
    if isinstance(old, list) and isinstance(new, list) and len(old) == len(new):
        out = []
        for i, (a, b) in enumerate(zip(old, new, strict=True)):
            label = a.get("id", i) if isinstance(a, dict) else i
            out += diff(a, b, f"{path}[{label}]")
        return out
    if old != new:
        return [f"{path}: {json.dumps(old)[:120]} -> {json.dumps(new)[:120]}"]
    return []


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--source", default=DEFAULT_SOURCE, help="ATLAS YAML path/URL")
    parser.add_argument("--json", default=str(TECHNIQUES_JSON), type=Path)
    parser.add_argument(
        "--check", action="store_true", help="validate only; exit 1 on drift"
    )
    args = parser.parse_args()

    current = json.loads(Path(args.json).read_text(encoding="utf-8"))
    up = Upstream(load_upstream(args.source), args.source)
    updated, errors = build(current, up)

    for err in errors:
        print(f"ERROR {err}", file=sys.stderr)

    if args.check:
        changes = diff(current, updated)
        for change in changes:
            print(f"DRIFT {change}")
        status = "in sync" if not changes and not errors else "out of sync"
        print(f"techniques.json is {status} with ATLAS {up.version}")
        return 1 if changes or errors else 0

    if errors:
        print("Not writing: fix the errors above first.", file=sys.stderr)
        return 1
    Path(args.json).write_text(
        json.dumps(updated, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(f"Wrote {args.json} from ATLAS {up.version}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
