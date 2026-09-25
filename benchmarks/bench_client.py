"""Network client benchmark against the local mock server.

Scenarios (all offline, loopback only):

``sequential``
    One probe at a time, as the RL loop in ``RedTeam.run`` sends them.
    Measures probes/s and how many TCP connections the client opened.

``fanout``
    A caller fans out a large batch with ``asyncio.gather`` over
    ``Target.send_probe_safe`` with a short timeout.  Measures wall time,
    failures, retries (server-side request count minus probes) and whether
    the ``latency_ms`` reported per probe reflects the target's real latency
    or includes time spent queueing for a pooled connection.

``batch_api``
    Same batch through ``Target.send_probes`` (bounded-concurrency helper).
    Skipped when the package under test does not provide it.

``idle_gap``
    Alternates attack-model generations and target probes with a pause
    between rounds longer than httpx's default 5 s keep-alive, as happens
    when either model is slow.  Counts TCP connections opened.

``stalled``
    The target sends headers immediately and then trickles the body for
    several seconds.  Measures how long ``send_probe_safe`` takes to give up
    relative to the configured ``timeout_seconds``.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import time
from typing import Any

from _common import MockServerHandle, mock_server, summarize

SEQUENTIAL_PROBES = 400
FANOUT_PROBES = 1500
FANOUT_LATENCY_MS = 25.0
FANOUT_TIMEOUT_S = 1.0
STALL_TIMEOUT_S = 0.5
STALL_SECONDS = 3.0
IDLE_ROUNDS = 4
IDLE_GAP_S = 6.0


def _target(endpoint: str, **kwargs: Any) -> Any:
    from infiltr.target import Target

    return Target(endpoint=endpoint, **kwargs)


def _is_timeout(result: object) -> bool:
    return not isinstance(result, tuple)


async def _sequential(server: MockServerHandle, probes: int) -> dict[str, Any]:
    target = _target(f"{server.base_url}/chat")
    await target.send_probe("warm-up")
    server.reset()
    start = time.perf_counter()
    for i in range(probes):
        await target.send_probe(f"sequential probe {i}")
    elapsed = time.perf_counter() - start
    await target.close()
    stats = server.stats()
    return {
        "probes": probes,
        "wall_s": elapsed,
        "probes_per_s": probes / elapsed,
        "server_connections": stats["connections"],
        "server_requests": stats["requests"],
    }


async def _fanout(server: MockServerHandle, *, use_batch_api: bool) -> dict[str, Any]:
    target = _target(
        f"{server.base_url}/chat",
        timeout_seconds=FANOUT_TIMEOUT_S,
    )
    await target.send_probe("warm-up")
    server.reset()
    prompts = [f"fanout probe {i}" for i in range(FANOUT_PROBES)]
    start = time.perf_counter()
    if use_batch_api:
        results = await target.send_probes(prompts)
    else:
        results = await asyncio.gather(*(target.send_probe_safe(p) for p in prompts))
    elapsed = time.perf_counter() - start
    await target.close()
    stats = server.stats()

    ok = [r for r in results if not _is_timeout(r)]
    latencies = [r[1] / 1000.0 for r in ok]
    return {
        "probes": FANOUT_PROBES,
        "server_latency_ms": FANOUT_LATENCY_MS,
        "timeout_s": FANOUT_TIMEOUT_S,
        "wall_s": elapsed,
        "succeeded": len(ok),
        "failed": len(results) - len(ok),
        "server_requests": stats["requests"],
        "retried_requests": stats["requests"] - len(ok),
        "server_connections": stats["connections"],
        "reported_latency_s": summarize(latencies) if latencies else None,
    }


async def _idle_gap(server: MockServerHandle) -> dict[str, Any]:
    from infiltr.attacks.generator import AttackGenerator
    from infiltr.models import AttackAction, AttackCategory

    target = _target(f"{server.base_url}/chat")
    generator = AttackGenerator(
        attack_model="mock-attacker",
        api_key="sk-bench-offline",
        api_base=f"{server.base_url}/v1",
    )
    action = AttackAction(
        mutation_operator="synonym_replacement",
        strategy="direct",
        escalation=0.5,
        category=AttackCategory.PROMPT_INJECTION,
    )
    server.reset()
    for round_index in range(IDLE_ROUNDS):
        if round_index:
            await asyncio.sleep(IDLE_GAP_S)
        prompt = await generator.generate(action)
        await target.send_probe(prompt)
    await generator.close()
    await target.close()
    stats = server.stats()
    return {
        "rounds": IDLE_ROUNDS,
        "gap_s": IDLE_GAP_S,
        "server_requests": stats["requests"],
        "server_connections": stats["connections"],
    }


async def _stalled(server: MockServerHandle) -> dict[str, Any]:
    target = _target(
        f"{server.base_url}/drip",
        timeout_seconds=STALL_TIMEOUT_S,
        max_retries=1,
    )
    start = time.perf_counter()
    result = await target.send_probe_safe("stall")
    elapsed = time.perf_counter() - start
    await target.close()
    return {
        "timeout_s": STALL_TIMEOUT_S,
        "max_retries": 1,
        "server_stall_s": STALL_SECONDS,
        "wall_s": elapsed,
        "timed_out": _is_timeout(result),
    }


def run() -> dict[str, Any]:
    from infiltr.logging import configure_logging
    from infiltr.target import Target

    configure_logging(level="ERROR")

    results: dict[str, Any] = {}
    with mock_server() as server:
        results["sequential_0ms"] = asyncio.run(_sequential(server, SEQUENTIAL_PROBES))
    with mock_server(latency_ms=5.0) as server:
        results["sequential_5ms"] = asyncio.run(_sequential(server, 200))
    with mock_server(latency_ms=FANOUT_LATENCY_MS) as server:
        results["fanout_gather"] = asyncio.run(_fanout(server, use_batch_api=False))
        if hasattr(Target, "send_probes"):
            results["fanout_batch_api"] = asyncio.run(
                _fanout(server, use_batch_api=True)
            )
    with mock_server() as server:
        results["idle_gap"] = asyncio.run(_idle_gap(server))
    with mock_server(drip_interval=0.1, drip_seconds=STALL_SECONDS) as server:
        results["stalled_target"] = asyncio.run(_stalled(server))
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.parse_args()
    print(json.dumps(run(), indent=2))


if __name__ == "__main__":
    main()
