# Benchmarks

infiltr ships an offline benchmark suite under [`benchmarks/`](../benchmarks).
It measures the parts of the tool whose cost is not dominated by the model
under test: CLI startup, the HTTP clients that talk to the target and to the
attack model, report generation, and an end-to-end scan. Everything runs
against a mock server on `127.0.0.1`; no request leaves the machine and no
API key is needed.

## Running it

```bash
pip install -e ".[dev]"

# Single run of the current checkout -> benchmarks/results/after.json
python benchmarks/run_all.py --label after

# Before/after: snapshot the old source, then alternate rounds so that
# both sides see the same drift in machine load.
mkdir -p .bench-baseline
git archive <rev> src | tar -x -C .bench-baseline
for r in 1 2 3; do
  python benchmarks/run_all.py --label before --revision <rev> \
      --pythonpath "$PWD/.bench-baseline/src" --startup-repeats 7 \
      --output benchmarks/results/before-$r.json
  python benchmarks/run_all.py --label after --startup-repeats 7 \
      --output benchmarks/results/after-$r.json
done

# Median across rounds -> Markdown table
python benchmarks/compare.py \
    --before benchmarks/results/before-*.json \
    --after benchmarks/results/after-*.json > benchmarks/results/comparison.md
```

`--pythonpath` puts another copy of the `infiltr` source ahead of the
installed package. Before and after then use the same harness, interpreter
and dependency versions, and only the code under test differs.
`--only startup|bench_report|bench_client|bench_scan` (repeatable) runs a
subset. One round takes a few minutes, and most of that is the "before"
startup benchmark, because every sample imports PyTorch.

## What is measured

| Script | What it does |
| --- | --- |
| `mock_server.py` | Threaded HTTP/1.1 server. `POST /chat` stands in for the target application and `POST /v1/chat/completions` for the OpenAI-compatible attack model. Replies are chosen deterministically by hashing the last user message, so refusals, hedges and compliant answers show up in a fixed mix. `POST /drip` sends a complete JSON body and then trickles whitespace for a few seconds. `GET /stats` returns the number of API requests and of distinct TCP connections that carried them since the last `POST /reset`. The server runs in its own process so it does not compete with the client under test for the GIL. |
| `bench_startup.py` | Wall-clock time of fresh interpreters running `python -c pass` (the floor), `import infiltr.cli`, `infiltr --help`, `infiltr version` and `infiltr report -o all` on a 200-finding results file. There are 2 warm-up runs, then 15 timed runs per command, and the median is reported. The script also records how many modules `import infiltr.cli` loads and whether torch, openai, httpx or jinja2 are among them. |
| `bench_report.py` | Loads a synthetic results document with 100 or 2000 findings into `ATLASReport` and times `load`, `to_json`, `to_html`, `to_sarif` and `compare_to` (30 or 8 repeats after one warm-up). It stores a SHA-256 digest of each output, with generation timestamps normalised, so a run can show that the reports are byte-for-byte unchanged. |
| `bench_client.py` | **sequential:** 400 probes with no server delay and 200 with 5 ms, sent one at a time the way the RL loop sends them. **fanout:** 1500 probes through `asyncio.gather(send_probe_safe(...))` against a target with 25 ms latency and `timeout_seconds=1`. It records failures, retries, connections used and the `latency_ms` each probe reports, then runs the same batch through `Target.send_probes` when that exists. **idle_gap:** 4 rounds of attack generation plus a probe, with 6 s pauses (longer than httpx's default 5 s keep-alive), counting connections. **stalled:** a trickling target with `timeout_seconds=0.5` and `max_retries=1`, timing how long it takes to give up. |
| `bench_scan.py` | A full `RedTeam.run()` with `max_interactions=150`, where both the target and the attack model are the mock server, followed by all three report writers. It runs 3 times after a warm-up and reports the median, plus the connections used. PyTorch is pinned to one thread (see the caveats below). |
| `run_all.py` | Runs everything and writes `benchmarks/results/<label>.json`, recording the Python version, platform, CPU count and revision. Each in-process benchmark runs in a fresh child interpreter. Proxy variables are removed from the environment and a dummy `OPENAI_API_KEY` is set. |
| `compare.py` | Turns two result files into a Markdown table. |

### Caveats

- Absolute numbers depend on the machine. Compare runs from the same host,
  and read the medians rather than single samples. The committed results
  come from a shared 4-vCPU container whose load average was well above 4
  from unrelated jobs. That is why the interpreter floor moves between
  rounds, and why rounds alternate between before and after. Treat changes
  under about 20% on the millisecond-scale rows as noise.
- The end-to-end scan's cost is almost all PyTorch policy inference and PPO
  updates. That work is identical before and after these changes, so the
  scan row is a regression check, not a speed-up claim.
- The scan benchmark pins PyTorch to one intra-op thread. In an earlier
  set of rounds with default threading, identical code swung between 1 s
  and 13 s on the busy host, because torch threads competed with the
  unrelated jobs. The scan rows in the committed results were re-run with
  one thread, alternating before and after, using `run_all.py --only
  bench_scan --update`. Each result file's `meta.rerun` field records this.
- Startup numbers include a warm OS page cache. That matches repeated CLI
  use on a developer machine or in CI, but not the very first run after
  installation.
- The mock server sets `TCP_NODELAY`. Without it, its separate header and
  body writes interact with delayed ACKs and add about 40 ms to every
  response. That is an artefact of the mock and would drown out everything
  else being measured.

## Results

Before is `e814431`, the parent of this work. After is the head of the
performance branch. There are three alternating rounds per side on the same
host. The raw data is in [`benchmarks/results/`](../benchmarks/results) as
`before-N.json` and `after-N.json`, and the table below is
`benchmarks/results/comparison.md`.

Before: `e814431` (3 rounds) | After: `95335d2` (3 rounds) | Python 3.11.15 | 4 CPUs | Linux-6.18.44-fc-v42-x86_64-with-glibc2.39

Each cell is the median across rounds of that round's value (itself a median of repeats where the benchmark repeats).

| Benchmark | Before | After | Change |
| --- | ---: | ---: | ---: |
| CLI: `python -c pass` (interpreter floor) | 21.0 ms | 19.1 ms | 1.1x faster |
| CLI: `import infiltr.cli` | 3681.9 ms | 131.7 ms | 28.0x faster |
| CLI: `infiltr --help` | 3541.2 ms | 184.5 ms | 19.2x faster |
| CLI: `infiltr version` | 3594.0 ms | 177.9 ms | 20.2x faster |
| CLI: `infiltr report -o all` (200 findings) | 3606.5 ms | 438.4 ms | 8.2x faster |
| CLI: modules loaded by `import infiltr.cli` | 1916 | 219 | 0.11x |
| Report: load 2000 findings | 36.1 ms | 25.9 ms | 1.4x faster |
| Report: `to_json` 2000 findings | 171.7 ms | 129.2 ms | 1.3x faster |
| Report: `to_html` 2000 findings | 47.2 ms | 40.5 ms | 1.2x faster |
| Report: `to_sarif` 2000 findings | 98.5 ms | 101.2 ms | 1.03x |
| Report: `compare_to` 2000 vs 2000 | 111.9 ms | 95.5 ms | 1.2x faster |
| Report: `to_json` 100 findings | 10.5 ms | 6.3 ms | 1.7x faster |
| Report: `to_html` 100 findings | 8.3 ms | 2.0 ms | 4.0x faster |
| Report: `to_sarif` 100 findings | 8.0 ms | 6.4 ms | 1.2x faster |
| Client: sequential probes/s (0 ms target) | 713/s | 806/s | 1.13x |
| Client: sequential, TCP connections used (400 probes) | 1 | 1 | 1.00x |
| Client: sequential probes/s (5 ms target) | 119/s | 122/s | 1.03x |
| Client: fan-out 1500 via gather, wall time | 21765.0 ms | 3437.6 ms | 6.3x faster |
| Client: fan-out 1500 via gather, failed probes | 739 | 0 | -100% |
| Client: fan-out 1500 via gather, TCP connections used | 761 | 20 | 0.03x |
| Client: fan-out reported `latency_ms` p50 (server: 25 ms) | 2649.9 ms | 37.0 ms | 71.5x faster |
| Client: fan-out reported `latency_ms` p95 (server: 25 ms) | 8679.7 ms | 88.8 ms | 97.7x faster |
| Client: fan-out 1500 via `send_probes`, wall time | n/a | 3261.1 ms |  |
| Client: 4 generate+probe rounds with 6 s idle gaps, TCP connections | 8 | 2 | 0.25x |
| Client: stalled target, time to give up (timeout 0.5 s x 2 attempts) | 3050.6 ms | 1029.8 ms | 3.0x faster |
| Scan: 150-interaction scan, total wall time | 1246.6 ms | 1279.5 ms | 1.03x |
| Scan: probes/s | 125/s | 127/s | 1.01x |
| Scan: TCP connections used | 2 | 2 | 1.00x |

Report output digests (timestamps normalised) are **identical** across every before and after round.

How to read the table:

- **CLI.** `import infiltr.cli` loads 219 modules instead of 1916, and
  none of them is torch, numpy, openai, httpx, jinja2 or pydantic. `--help`
  and `version` are now within about 170 ms of the bare interpreter. The
  `report` command still imports Jinja2 and pydantic, but it no longer
  imports PyTorch.
- **Report.** The large win is on small reports, which is what real scans
  produce because findings are de-duplicated by technique and category.
  There, the one-time template compile used to be most of the cost. On
  2000-finding documents the remaining time goes to the standard library's
  indented JSON encoder and to Jinja2 rendering. Single-digit or
  low-double-digit percentage changes on those rows are within noise.
- **Client, sequential.** The sequential path already reused a single
  connection, and its throughput is unchanged within noise. A separate
  interleaved A/B on the same host gave 440 to 770 probes/s for both
  versions. The per-probe semaphore and deadline add no measurable cost.
- **Client, fan-out.** This is where the old client broke down. Requests
  queued in the httpx pool: 739 of 1500 probes failed with `PoolTimeout`,
  761 connections were opened for 761 successful requests, and the
  reported `latency_ms` was about 100 times the target's real latency. The
  bounded client finishes all 1500 probes on 20 kept-alive connections,
  and it reports latencies that match the server.
- **Client, idle gap.** With httpx's 5 s keep-alive, all 8 calls (4
  generations and 4 probes) opened a fresh connection. With the 30 s
  keep-alive, 2 connections serve all of them.
- **Client, stalled target.** The configured 0.5 s timeout now holds: two
  attempts take about 1.0 s. Before, a trickling server kept each attempt
  alive until it finished, and the probe "succeeded" after 3 s.
- **Scan.** The scan rows are unchanged. This is expected: the scan is
  dominated by policy inference and PPO updates, and against the
  zero-latency mock it never waits long enough for keep-alive to matter.

## What changed and why

### CLI startup

`infiltr/__init__.py` re-exported `RedTeam`, `Target` and `ATLASReport`
eagerly, and `infiltr/atlas/__init__.py` did the same for its submodules.
As a result, any `import infiltr.*`, including the one Typer runs to build
`infiltr --help`, loaded PyTorch, NumPy, the OpenAI SDK, httpx, Jinja2 and
pydantic. Now:

- Both packages resolve their public names on first attribute access
  (PEP 562 `__getattr__`). `from infiltr import RedTeam` keeps working, and
  type checkers still see the real symbols.
- `infiltr.__version__` reads package metadata only when first accessed.
- `cli.py` keeps only `typer` and `rich.console` at module level. `asyncio`,
  structlog, rich widgets, the report and baseline helpers and the RL stack
  are imported inside the command that needs them.

`infiltr scan` still imports everything, but only once it has something to
run.

### Network clients

- **Bounded concurrency.** `Target` holds a semaphore sized to the new
  `max_concurrency` setting. The default is 20, the old pool size. The
  connection pool is sized to match, and every connection is kept alive.
  Before this change, a caller that fanned out queued inside httpx's pool.
  That wait counted against `timeout_seconds` and caused spurious
  `PoolTimeout` failures, and it was included in the reported
  `latency_ms`, which skewed the budget p95 metrics. The queue also churned
  connections. The slot is now taken before the clock starts.
- **Batch helper.** `Target.send_probes(prompts, concurrency=...)` runs a
  fixed pool of workers rather than one task per prompt, returns results
  in input order and behaves like `send_probe_safe` for each prompt.
- **Keep-alive.** Idle connections to the target and to the attack model
  are kept for 30 s instead of httpx's 5 s. Between two probes the tool
  waits for an attack-model generation, and between two generations it
  waits for a probe. Either can take more than 5 s, which used to force a
  new TCP and TLS handshake on almost every call. The attack model's
  connection limits, timeouts and redirect policy stay at the OpenAI SDK
  defaults.
- **Timeouts.** `timeout_seconds` is now a deadline for each attempt as a
  whole. httpx applies its timeouts to each network operation, so a target
  that trickled bytes never timed out. The connect phase is capped at 10 s,
  so an unreachable target fails fast even with a generous response
  timeout.

The sequential probe loop, retry policy, request bodies and response parsing
are unchanged. What gets sent to the target, and how responses are scored,
is unchanged too.

### Report generation

- The HTML template is compiled once per process. Building a new Jinja2
  `Environment` and recompiling the template on every call was most of the
  cost of rendering a typical report, which after de-duplication holds at
  most a few dozen findings.
- Severities are counted in one pass instead of one pass per level.
- Findings are serialised with `model_dump(mode="json")` instead of a
  `model_dump_json()` → `json.loads()` round trip.

The output digests in the results show that the JSON, HTML and SARIF output
is identical before and after. For very large reports, most of the remaining
`to_json` and `to_sarif` time is the standard library's pure-Python encoder,
which `json.dumps` uses whenever `indent` is set. It stays, so the output
format does not change.
