# infiltr

[![CI](https://github.com/sushaan-k/infiltr/actions/workflows/ci.yml/badge.svg)](https://github.com/sushaan-k/infiltr/actions)
[![PyPI](https://img.shields.io/pypi/v/infiltr.svg)](https://pypi.org/project/infiltr/)
[![PyPI Downloads](https://img.shields.io/pypi/dm/infiltr.svg)](https://pypi.org/project/infiltr/)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![MITRE ATLAS](https://img.shields.io/badge/MITRE-ATLAS-red.svg)](https://atlas.mitre.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**RL-based adversarial red-teaming for LLMs, with MITRE ATLAS reporting.**

`infiltr` trains an attack policy via reinforcement learning to discover jailbreaks, prompt injections, and policy violations in your deployed LLM systems — then maps every finding to a [MITRE ATLAS](https://atlas.mitre.org) technique so your security team speaks the same language as the threat.

---

## The Problem

Manual red-teaming is one-and-done. Static attack libraries go stale in days. Model providers test their own models. Nobody is running **adaptive adversarial search** against *your* fine-tuned deployment with *your* system prompt. Enterprise AI security teams have no standard taxonomy to file findings under, so issues slip through the cracks between ML teams and InfoSec.

## Solution

```python
from phantom import RedTeamSession, Target, TargetConfig

target = Target(config=TargetConfig(
    endpoint="https://your-api.com/chat",
    auth={"Authorization": "Bearer YOUR_KEY"},
    system_prompt_known=True,
    system_prompt="You are a helpful customer support agent for Acme Corp...",
))

session = RedTeamSession(target=target, budget=500)
report = await session.run()

print(report.summary())
# Found 14 vulnerabilities across 6 ATLAS techniques
# Critical: AML.T0054 (LLM Prompt Injection) — 3 reproducible exploits
# High:     AML.T0048 (Societal Harm)         — 5 reproducible exploits
```

## At a Glance

- **RL attack policy** trained on your target's live responses — adapts as defenses change
- **Genetic mutation engine** — splices, substitutes, and recombines successful attack fragments
- **MITRE ATLAS mapping** — every finding tagged to a technique, tactic, and mitigation
- **Reproducible PoCs** — each finding ships with a minimal reproduction case
- **Differential testing** — compares behavior against a reference model to catch regressions

## Install

```bash
pip install infiltr
```

## Attack Taxonomy Coverage

| ATLAS Tactic | Techniques Covered |
|---|---|
| Initial Access | Prompt Injection, Indirect Injection, Data Poisoning |
| Execution | Jailbreak, Role Confusion, Context Overflow |
| Exfiltration | Training Data Extraction, System Prompt Leak |
| Impact | Societal Harm, Denial of Service, Financial Harm |

## Architecture

```
RedTeamSession
 ├── AttackGenerator    # mutation-based attack synthesis
 ├── PolicyNetwork      # PPO-trained attack selection policy
 ├── Target             # async HTTP wrapper for any LLM endpoint
 ├── RewardClassifier   # scores responses for policy violations
 └── ATLASMapper        # maps findings → MITRE ATLAS techniques
```

## Contributing

PRs welcome. Run `pip install -e ".[dev]"` then `pytest`. Star the repo if you find it useful ⭐
