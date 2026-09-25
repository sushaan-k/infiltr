"""Run the full offline benchmark suite and write a results JSON file.

Usage::

    python benchmarks/run_all.py --label after
    python benchmarks/run_all.py --label before --pythonpath /path/to/old/src

``--pythonpath`` points the suite at a different copy of the ``infiltr``
source tree (for example a ``git archive`` of an older commit) so that
"before" and "after" are measured with the same harness, interpreter,
dependencies and machine.  Each in-process benchmark runs in its own child
interpreter so that module caches never leak between benchmarks.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import bench_startup
from _common import BENCH_DIR, subprocess_env, write_json

CHILD_BENCHMARKS = ("bench_report", "bench_client", "bench_scan")


def _run_child(name: str, pythonpath: str | None) -> dict[str, Any]:
    env = subprocess_env(pythonpath)
    # The harness modules live next to this file; the package under test comes
    # from ``pythonpath`` (if given) or the installed/editable distribution.
    env["PYTHONPATH"] = os.pathsep.join(p for p in (pythonpath, str(BENCH_DIR)) if p)
    completed = subprocess.run(
        [sys.executable, str(BENCH_DIR / f"{name}.py")],
        env=env,
        cwd=BENCH_DIR,
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"{name} failed:\n{completed.stderr[-2000:]}")
    result: dict[str, Any] = json.loads(completed.stdout)
    return result


def _git_revision() -> str:
    """Short revision of the checkout the harness lives in (``-dirty`` if so)."""
    try:
        rev = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=BENCH_DIR,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        dirty = subprocess.run(
            ["git", "status", "--porcelain", "--", "src"],
            cwd=BENCH_DIR.parent,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"
    return f"{rev}-dirty" if dirty else rev


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--label", required=True)
    parser.add_argument("--pythonpath", default=None)
    parser.add_argument(
        "--revision",
        default=None,
        help="Revision label of the code under test (default: this checkout).",
    )
    parser.add_argument("--startup-repeats", type=int, default=15)
    parser.add_argument(
        "--only",
        choices=["startup", *CHILD_BENCHMARKS],
        action="append",
        help="Run only the named benchmark(s).",
    )
    parser.add_argument(
        "--update",
        action="store_true",
        help="Merge the selected benchmarks into an existing results file.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Results file (default: benchmarks/results/<label>.json).",
    )
    args = parser.parse_args()

    selected = args.only or ["startup", *CHILD_BENCHMARKS]
    output = args.output or BENCH_DIR / "results" / f"{args.label}.json"
    previous: dict[str, Any] = {}
    if args.update and output.exists():
        previous = json.loads(output.read_text())
    results: dict[str, Any] = {
        **previous,
        "meta": {
            "label": args.label,
            "revision": args.revision or _git_revision(),
            "python": platform.python_version(),
            "platform": platform.platform(),
            "cpu_count": os.cpu_count(),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        },
    }
    for name in selected:
        print(f"[{args.label}] running {name} ...", file=sys.stderr, flush=True)
        start = time.perf_counter()
        if name == "startup":
            results[name] = bench_startup.run(args.pythonpath, args.startup_repeats)
        else:
            results[name] = _run_child(name, args.pythonpath)
        print(
            f"[{args.label}] {name} done in {time.perf_counter() - start:.1f}s",
            file=sys.stderr,
            flush=True,
        )

    write_json(output, results)
    print(f"wrote {output}", file=sys.stderr)


if __name__ == "__main__":
    main()
