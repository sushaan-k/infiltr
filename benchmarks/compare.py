"""Render a Markdown before/after table from two ``run_all.py`` result files.

Usage::

    python benchmarks/compare.py benchmarks/results/before.json \\
        benchmarks/results/after.json > benchmarks/results/comparison.md
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

Row = tuple[str, Callable[[dict[str, Any]], float | None], str]


def _get(data: dict[str, Any], *path: str) -> Any:
    node: Any = data
    for key in path:
        if not isinstance(node, dict) or key not in node:
            return None
        node = node[key]
    return node


def _median(*path: str, scale: float = 1.0) -> Callable[[dict[str, Any]], float | None]:
    def extract(data: dict[str, Any]) -> float | None:
        value = _get(data, *path, "median")
        return None if value is None else float(value) * scale

    return extract


def _median_ms(*path: str) -> Callable[[dict[str, Any]], float | None]:
    return _median(*path, scale=1000.0)


def _value(*path: str, scale: float = 1.0) -> Callable[[dict[str, Any]], float | None]:
    def extract(data: dict[str, Any]) -> float | None:
        value = _get(data, *path)
        if value is None or isinstance(value, bool):
            return None
        return float(value) * scale

    return extract


def _scan_first(key: str) -> Callable[[dict[str, Any]], float | None]:
    def extract(data: dict[str, Any]) -> float | None:
        values = _get(data, "bench_scan", key)
        return float(values[0]) if values else None

    return extract


ROWS: list[Row] = [
    (
        "CLI: `python -c pass` (interpreter floor)",
        _median_ms("startup", "python_baseline"),
        "ms",
    ),
    ("CLI: `import infiltr.cli`", _median_ms("startup", "import_infiltr_cli"), "ms"),
    ("CLI: `infiltr --help`", _median_ms("startup", "cli_help"), "ms"),
    ("CLI: `infiltr version`", _median_ms("startup", "cli_version"), "ms"),
    (
        "CLI: `infiltr report -o all` (200 findings)",
        _median_ms("startup", "cli_report_all_200"),
        "ms",
    ),
    (
        "CLI: modules loaded by `import infiltr.cli`",
        _value("startup", "import_footprint", "modules"),
        "count",
    ),
    (
        "Report: load 2000 findings",
        _median_ms("bench_report", "findings_2000", "load"),
        "ms",
    ),
    (
        "Report: `to_json` 2000 findings",
        _median_ms("bench_report", "findings_2000", "to_json"),
        "ms",
    ),
    (
        "Report: `to_html` 2000 findings",
        _median_ms("bench_report", "findings_2000", "to_html"),
        "ms",
    ),
    (
        "Report: `to_sarif` 2000 findings",
        _median_ms("bench_report", "findings_2000", "to_sarif"),
        "ms",
    ),
    (
        "Report: `compare_to` 2000 vs 2000",
        _median_ms("bench_report", "findings_2000", "compare_to"),
        "ms",
    ),
    (
        "Report: `to_json` 100 findings",
        _median_ms("bench_report", "findings_100", "to_json"),
        "ms",
    ),
    (
        "Report: `to_html` 100 findings",
        _median_ms("bench_report", "findings_100", "to_html"),
        "ms",
    ),
    (
        "Report: `to_sarif` 100 findings",
        _median_ms("bench_report", "findings_100", "to_sarif"),
        "ms",
    ),
    (
        "Client: sequential probes/s (0 ms target)",
        _value("bench_client", "sequential_0ms", "probes_per_s"),
        "/s",
    ),
    (
        "Client: sequential TCP connections (400 probes)",
        _value("bench_client", "sequential_0ms", "server_connections"),
        "count",
    ),
    (
        "Client: sequential probes/s (5 ms target)",
        _value("bench_client", "sequential_5ms", "probes_per_s"),
        "/s",
    ),
    (
        "Client: fan-out 1500 via gather, wall time",
        _value("bench_client", "fanout_gather", "wall_s", scale=1000.0),
        "ms",
    ),
    (
        "Client: fan-out 1500 via gather, failed probes",
        _value("bench_client", "fanout_gather", "failed"),
        "count",
    ),
    (
        "Client: fan-out 1500 via gather, TCP connections",
        _value("bench_client", "fanout_gather", "server_connections"),
        "count",
    ),
    (
        "Client: fan-out reported latency p50 (target: 25 ms)",
        _median_ms("bench_client", "fanout_gather", "reported_latency_s"),
        "ms",
    ),
    (
        "Client: fan-out 1500 via `send_probes`, wall time",
        _value("bench_client", "fanout_batch_api", "wall_s", scale=1000.0),
        "ms",
    ),
    (
        "Client: stalled target, time to give up (timeout 0.5 s x 2 attempts)",
        _value("bench_client", "stalled_target", "wall_s", scale=1000.0),
        "ms",
    ),
    (
        "Scan: 150-interaction scan, total wall time",
        _median_ms("bench_scan", "total_s"),
        "ms",
    ),
    ("Scan: probes/s", _median("bench_scan", "probes_per_s"), "/s"),
    ("Scan: TCP connections opened", _scan_first("server_connections"), "count"),
]


def _fmt(value: float | None, unit: str) -> str:
    if value is None:
        return "n/a"
    if unit == "count":
        return f"{value:.0f}"
    if unit == "/s":
        return f"{value:.0f}/s"
    return f"{value:.1f} ms"


def _change(before: float | None, after: float | None, unit: str) -> str:
    if before is None or after is None:
        return ""
    if before == 0:
        return "" if after == 0 else "new"
    ratio = after / before
    if unit == "/s":
        return f"{ratio:.2f}x"
    if ratio == 0:
        return "-100%"
    if ratio < 1:
        return f"{1 / ratio:.1f}x faster" if unit == "ms" else f"{ratio:.2f}x"
    return f"{ratio:.2f}x"


def render(before: dict[str, Any], after: dict[str, Any]) -> str:
    lines = [
        f"Before: `{before['meta'].get('revision')}` | "
        f"After: `{after['meta'].get('revision')}` | "
        f"Python {after['meta'].get('python')} | "
        f"{after['meta'].get('cpu_count')} CPUs | "
        f"{after['meta'].get('platform')}",
        "",
        "| Benchmark | Before | After | Change |",
        "| --- | ---: | ---: | ---: |",
    ]
    for label, extract, unit in ROWS:
        b, a = extract(before), extract(after)
        if b is None and a is None:
            continue
        lines.append(
            f"| {label} | {_fmt(b, unit)} | {_fmt(a, unit)} | {_change(b, a, unit)} |"
        )

    digests_b = _get(before, "bench_report", "output_digests") or {}
    digests_a = _get(after, "bench_report", "output_digests") or {}
    if digests_a:
        same = digests_a == digests_b
        lines += [
            "",
            "Report output digests (timestamps normalised) "
            + ("are **identical** before and after." if same else "**differ**:"),
        ]
        if not same:
            for key in sorted(set(digests_a) | set(digests_b)):
                lines.append(f"- {key}: {digests_b.get(key)} -> {digests_a.get(key)}")
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("before", type=Path)
    parser.add_argument("after", type=Path)
    args = parser.parse_args()
    before = json.loads(args.before.read_text())
    after = json.loads(args.after.read_text())
    print(render(before, after), end="")


if __name__ == "__main__":
    main()
