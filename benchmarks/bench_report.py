"""Report generation benchmark.

Loads a synthetic results document into :class:`infiltr.ATLASReport` and
times the JSON / HTML / SARIF writers plus baseline comparison.  It also
records a digest of each output (with generation timestamps normalised) so
that runs against different versions of the package can prove the rendered
reports are byte-for-byte identical.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import tempfile
import time
from collections.abc import Callable
from functools import partial
from pathlib import Path
from typing import Any

from _common import summarize, synthetic_report

SIZES: dict[int, int] = {100: 30, 2000: 8}  # findings -> repeats

_HTML_TS = re.compile(r"Generated \d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC")


def _timeit(fn: Callable[[], object], repeats: int) -> dict[str, float]:
    fn()  # warm-up (template compilation, first-call caches, ...)
    samples = []
    for _ in range(repeats):
        start = time.perf_counter()
        fn()
        samples.append(time.perf_counter() - start)
    return summarize(samples)


def _digest(path: Path, kind: str) -> str:
    text = path.read_text(encoding="utf-8")
    if kind == "json":
        data = json.loads(text)
        data.pop("generated_at", None)
        data.pop("infiltr_version", None)
        text = json.dumps(data, sort_keys=True)
    elif kind == "html":
        text = _HTML_TS.sub("Generated <ts>", text)
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def _load(report_cls: Any, raw: str) -> object:
    return report_cls(json.loads(raw))


def run(sizes: dict[int, int] | None = None) -> dict[str, Any]:
    from infiltr.atlas.report import ATLASReport
    from infiltr.logging import configure_logging

    configure_logging(level="WARNING")

    results: dict[str, Any] = {}
    digests: dict[str, str] = {}
    with tempfile.TemporaryDirectory(prefix="infiltr-bench-") as tmp:
        out = Path(tmp)
        for count, repeats in (sizes or SIZES).items():
            document = synthetic_report(count)
            raw = json.dumps(document)
            report = ATLASReport(json.loads(raw))
            baseline = ATLASReport(json.loads(raw))

            timings = {
                "load": _timeit(partial(_load, ATLASReport, raw), repeats),
                "to_json": _timeit(partial(report.to_json, out / "r.json"), repeats),
                "to_html": _timeit(partial(report.to_html, out / "r.html"), repeats),
                "to_sarif": _timeit(partial(report.to_sarif, out / "r.sarif"), repeats),
                "compare_to": _timeit(partial(report.compare_to, baseline), repeats),
            }
            results[f"findings_{count}"] = timings
            for kind in ("json", "html", "sarif"):
                digests[f"{kind}_{count}"] = _digest(out / f"r.{kind}", kind)

    results["output_digests"] = digests
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.parse_args()
    print(json.dumps(run(), indent=2))


if __name__ == "__main__":
    main()
