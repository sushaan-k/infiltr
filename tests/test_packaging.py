"""Packaging guards: typing marker, version, and console-script entry points."""

from __future__ import annotations

from importlib import metadata
from importlib.resources import files

import infiltr


def test_version_is_exposed() -> None:
    assert isinstance(infiltr.__version__, str)
    assert infiltr.__version__


def test_py_typed_marker_ships() -> None:
    marker = files("infiltr") / "py.typed"
    assert marker.is_file()


def test_techniques_data_ships() -> None:
    data = files("infiltr.atlas") / "data" / "techniques.json"
    assert data.is_file()


def test_console_scripts_resolve() -> None:
    scripts = {
        ep.name: ep.value
        for ep in metadata.entry_points(group="console_scripts")
        if ep.name in {"infiltr", "phantom"}
    }
    # The primary command and the legacy alias both point at the CLI app.
    assert scripts.get("infiltr") == "infiltr.cli:app"
    assert scripts.get("phantom") == "infiltr.cli:app"
