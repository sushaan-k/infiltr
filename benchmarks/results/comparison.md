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
