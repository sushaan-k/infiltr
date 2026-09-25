"""CLI startup benchmark.

Spawns fresh interpreters and measures wall-clock time for common CLI
invocations.  Every sample is a cold interpreter start (the OS page cache is
warm after the warm-up runs, as it would be on a developer machine or a CI
runner that has just installed the package).
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from _common import subprocess_env, summarize, synthetic_report

REPORT_FINDINGS = 200


def _time_command(cmd: list[str], env: dict[str, str], cwd: Path) -> float:
    start = time.perf_counter()
    completed = subprocess.run(
        cmd,
        env=env,
        cwd=cwd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        check=False,
    )
    elapsed = time.perf_counter() - start
    if completed.returncode != 0:
        raise RuntimeError(
            f"{cmd!r} exited {completed.returncode}: {completed.stderr.decode()[-500:]}"
        )
    return elapsed


def _module_probe(env: dict[str, str], cwd: Path) -> dict[str, Any]:
    """Report how much of the dependency tree ``import infiltr.cli`` loads."""
    code = (
        "import sys, json, infiltr.cli; "
        "print(json.dumps({'modules': len(sys.modules), "
        "'torch_loaded': 'torch' in sys.modules, "
        "'openai_loaded': 'openai' in sys.modules, "
        "'httpx_loaded': 'httpx' in sys.modules, "
        "'jinja2_loaded': 'jinja2' in sys.modules}))"
    )
    out = subprocess.run(
        [sys.executable, "-c", code],
        env=env,
        cwd=cwd,
        capture_output=True,
        text=True,
        check=True,
    )
    result: dict[str, Any] = json.loads(out.stdout)
    return result


def run(pythonpath: str | None, repeats: int, warmup: int = 2) -> dict[str, Any]:
    env = subprocess_env(pythonpath)
    py = sys.executable
    with tempfile.TemporaryDirectory(prefix="infiltr-bench-") as tmp:
        cwd = Path(tmp)
        report_input = cwd / "input.json"
        report_input.write_text(json.dumps(synthetic_report(REPORT_FINDINGS)))

        commands: dict[str, list[str]] = {
            "python_baseline": [py, "-c", "pass"],
            "import_infiltr_cli": [py, "-c", "import infiltr.cli"],
            "cli_help": [py, "-m", "infiltr", "--help"],
            "cli_version": [py, "-m", "infiltr", "version"],
            "cli_report_all_200": [
                py,
                "-m",
                "infiltr",
                "report",
                "-i",
                str(report_input),
                "-o",
                "all",
                "-p",
                str(cwd / "out"),
            ],
        }

        results: dict[str, Any] = {}
        for name, cmd in commands.items():
            for _ in range(warmup):
                _time_command(cmd, env, cwd)
            samples = [_time_command(cmd, env, cwd) for _ in range(repeats)]
            results[name] = summarize(samples)

        results["import_footprint"] = _module_probe(env, cwd)
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--pythonpath", default=None)
    parser.add_argument("--repeats", type=int, default=15)
    args = parser.parse_args()
    print(json.dumps(run(args.pythonpath, args.repeats), indent=2))


if __name__ == "__main__":
    main()
