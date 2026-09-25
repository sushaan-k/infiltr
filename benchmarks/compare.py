"""Render a Markdown before/after table from ``run_all.py`` result files.

Usage::

    python benchmarks/compare.py \\
        --before benchmarks/results/before-*.json \\
        --after benchmarks/results/after-*.json > benchmarks/results/comparison.md

When several files are given per side (interleaved rounds), each metric is
the median of the per-round values, which damps drift on a shared host.
"""

from __future__ import annotations

import argparse
import json
import statistics
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
        "Client: sequential, TCP connections used (400 probes)",
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
        "Client: fan-out 1500 via gather, TCP connections used",
        _value("bench_client", "fanout_gather", "server_connections"),
        "count",
    ),
    (
        "Client: fan-out reported `latency_ms` p50 (server: 25 ms)",
        _median_ms("bench_client", "fanout_gather", "reported_latency_s"),
        "ms",
    ),
    (
        "Client: fan-out reported `latency_ms` p95 (server: 25 ms)",
        _value(
            "bench_client", "fanout_gather", "reported_latency_s", "p95", scale=1000.0
        ),
        "ms",
    ),
    (
        "Client: fan-out 1500 via `send_probes`, wall time",
        _value("bench_client", "fanout_batch_api", "wall_s", scale=1000.0),
        "ms",
    ),
    (
        "Client: 4 generate+probe rounds with 6 s idle gaps, TCP connections",
        _value("bench_client", "idle_gap", "server_connections"),
        "count",
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
    ("Scan: TCP connections used", _scan_first("server_connections"), "count"),
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


def _median_of(values: list[float | None]) -> float | None:
    present = [v for v in values if v is not None]
    return statistics.median(present) if present else None


def render(befores: list[dict[str, Any]], afters: list[dict[str, Any]]) -> str:
    before_meta, after_meta = befores[0]["meta"], afters[0]["meta"]
    lines = [
        f"Before: `{before_meta.get('revision')}` ({len(befores)} rounds) | "
        f"After: `{after_meta.get('revision')}` ({len(afters)} rounds) | "
        f"Python {after_meta.get('python')} | "
        f"{after_meta.get('cpu_count')} CPUs | "
        f"{after_meta.get('platform')}",
        "",
        "Each cell is the median across rounds of that round's value (itself a "
        "median of repeats where the benchmark repeats).",
        "",
        "| Benchmark | Before | After | Change |",
        "| --- | ---: | ---: | ---: |",
    ]
    for label, extract, unit in ROWS:
        b = _median_of([extract(run) for run in befores])
        a = _median_of([extract(run) for run in afters])
        if b is None and a is None:
            continue
        lines.append(
            f"| {label} | {_fmt(b, unit)} | {_fmt(a, unit)} | {_change(b, a, unit)} |"
        )

    digest_sets = [
        _get(run, "bench_report", "output_digests") or {} for run in befores + afters
    ]
    if any(digest_sets):
        same = all(d == digest_sets[0] for d in digest_sets)
        lines += [
            "",
            "Report output digests (timestamps normalised) "
            + (
                "are **identical** across every before and after round."
                if same
                else "**differ** between runs."
            ),
        ]
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--before", type=Path, nargs="+", required=True)
    parser.add_argument("--after", type=Path, nargs="+", required=True)
    args = parser.parse_args()
    befores = [json.loads(path.read_text()) for path in args.before]
    afters = [json.loads(path.read_text()) for path in args.after]
    print(render(befores, afters), end="")


if __name__ == "__main__":
    main()
