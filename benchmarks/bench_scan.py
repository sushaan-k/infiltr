"""End-to-end scan benchmark.

Runs a complete ``RedTeam.run()`` assessment in which both the target
application and the attack model are served by the local mock server, then
writes all three report formats.  This exercises the real probe loop (policy
selection, attack generation through the ``openai`` SDK, target probing,
reward classification, PPO updates, ATLAS mapping) with no external network.

PyTorch is pinned to one intra-op thread.  The policy network is tiny, so
multi-threaded kernels buy nothing, while on a busy host their thread
contention made wall time swing by an order of magnitude between otherwise
identical runs and drowned out everything else in this benchmark.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import tempfile
import time
from pathlib import Path
from typing import Any

from _common import mock_server, summarize

INTERACTIONS = 150
REPEATS = 3


async def _scan(base_url: str, out_dir: Path) -> dict[str, float]:
    import torch

    from infiltr.atlas.report import ATLASReport
    from infiltr.redteam import RedTeam
    from infiltr.target import Target

    torch.manual_seed(0)
    start = time.perf_counter()
    target = Target(endpoint=f"{base_url}/chat")
    red_team = RedTeam(
        target=target,
        attack_model="mock-attacker",
        attack_api_key="sk-bench-offline",
        attack_api_base=f"{base_url}/v1",
        max_interactions=INTERACTIONS,
    )
    constructed = time.perf_counter()
    results = await red_team.run()
    scanned = time.perf_counter()
    report = ATLASReport(results)
    report.to_json(out_dir / "scan.json")
    report.to_html(out_dir / "scan.html")
    report.to_sarif(out_dir / "scan.sarif")
    reported = time.perf_counter()
    return {
        "setup_s": constructed - start,
        "scan_s": scanned - constructed,
        "report_s": reported - scanned,
        "total_s": reported - start,
        "probes": float(results.total_probes),
    }


def run() -> dict[str, Any]:
    import torch

    from infiltr.logging import configure_logging

    configure_logging(level="ERROR")
    torch.set_num_threads(1)

    runs: list[dict[str, float]] = []
    connections: list[int] = []
    requests: list[int] = []
    with (
        mock_server() as server,
        tempfile.TemporaryDirectory(prefix="infiltr-bench-") as tmp,
    ):
        asyncio.run(_scan(server.base_url, Path(tmp)))  # warm-up
        for _ in range(REPEATS):
            server.reset()
            runs.append(asyncio.run(_scan(server.base_url, Path(tmp))))
            stats = server.stats()
            connections.append(stats["connections"])
            requests.append(stats["requests"])

    probes = [r["probes"] for r in runs]
    return {
        "torch_threads": torch.get_num_threads(),
        "interactions": INTERACTIONS,
        "probes": probes,
        "setup_s": summarize([r["setup_s"] for r in runs]),
        "scan_s": summarize([r["scan_s"] for r in runs]),
        "report_s": summarize([r["report_s"] for r in runs]),
        "total_s": summarize([r["total_s"] for r in runs]),
        "probes_per_s": summarize([r["probes"] / r["scan_s"] for r in runs]),
        "server_connections": connections,
        "server_requests": requests,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.parse_args()
    print(json.dumps(run(), indent=2))


if __name__ == "__main__":
    main()
