# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0]

### Changed (breaking)

- Renamed the distribution, import package, and primary CLI command to
  `infiltr` (previously distributed as `phantom-redteam`, importing `phantom`,
  with a `phantom` command).
  - **Migration** — imports: `from phantom import ...` becomes
    `from infiltr import ...`.
  - **Migration** — CLI: `phantom scan ...` becomes `infiltr scan ...`. The
    `phantom` command is kept as a legacy alias and continues to work.
  - `PhantomError` is now `InfiltrError`; the `PHANTOM_FAIL_ON_HIGH` example
    env var is now `INFILTR_FAIL_ON_HIGH`.
- `__version__` is now read from the installed package metadata (falls back to
  `"0+unknown"` in a source tree), and report branding uses it instead of a
  hard-coded string.

- The bundled MITRE ATLAS taxonomy is now sourced from the official
  [mitre-atlas/atlas-data](https://github.com/mitre-atlas/atlas-data) release
  2026.09 (format 6.0.0). Several previously shipped IDs were invented or
  outdated and are corrected:
  - `AML.T0054.000`/`.001`/`.002` ("Goal Hijacking", "System Prompt
    Extraction", "Tool Manipulation") do not exist in ATLAS. Goal hijacking
    now maps to `AML.T0054` LLM Jailbreak; system prompt extraction is
    `AML.T0056`; tool abuse is `AML.T0053` AI Agent Tool Invocation.
  - `AML.T0051.002` is "Triggered", not multi-turn. Multi-turn escalation
    now maps to `AML.T0054`, which ATLAS lists as a jailbreak strategy.
    Prompt-injection probes from the indirect strategy map to `AML.T0051.001`.
  - `AML.T0024.000`–`.002` are membership inference, model inversion and model
    extraction. Data-exfiltration findings (PII, credentials, configuration)
    now map to `AML.T0057` LLM Data Leakage.
  - `AML.T0029` has no sub-techniques; resource exhaustion and reputational
    harm live under `AML.T0034` Cost Harvesting and `AML.T0048.001`.
  - `AML.T0043.004` is "Insert Backdoor Trigger" and `AML.T0047` is
    "AI-Enabled Product or Service"; the entries misusing them were replaced by
    `AML.T0056` and `AML.T0010.005` (AI Supply Chain Compromise: AI Agent Tool).
  - Tactics now match ATLAS (e.g. LLM Prompt Injection is Execution, not
    Initial Access; techniques may list several tactics).
- Coverage expanded to 21 techniques / 42 IDs across 10 tactics, each with its
  official description, tactics and ATLAS mitigations (`AML.M*` IDs) plus
  infiltr remediation guidance. Finding remediation text now combines the
  technique's guidance with its official mitigations for every technique.
- Findings for sub-techniques are named `"<technique>: <sub-technique>"`
  (e.g. `LLM Prompt Injection: Direct`), matching atlas.mitre.org.
- `Technique.mitigations` and `ATLASTaxonomy.get_mitigations()` return
  `Mitigation` objects (`id`, `name`; `str()` gives `"AML.M0020 Generative AI
  Guardrails"`) instead of strings. `Technique` gains `tactics` and
  `remediation`.
  - **Migration** — baselines: finding fingerprints include the technique ID,
    so regenerate `--baseline` reports after upgrading; otherwise findings
    whose ID changed are reported as new.
  - `RedTeamResults.atlas_coverage_pct` is now relative to the larger taxonomy.

### Added

- `scripts/sync_atlas.py`, a maintainer tool (not run in CI, not a runtime
  dependency) that re-syncs `techniques.json` from upstream ATLAS or, with
  `--check`, reports drift.
- An offline test that validates every ATLAS ID in the bundled data and that
  every attack-category mapping resolves.
- `ATLASTaxonomy.version`, `.tactics`, `.techniques`, `get_category_mapping()`,
  `get_display_name()` and `get_remediation()`. Category mappings are read from
  `techniques.json` instead of being duplicated in the mapper.
- Probes record their attack strategy in `ProbeResult.metadata["strategy"]`.

### Fixed

- `RedTeamConfig.seed` was accepted but never applied; runs are now
  reproducible. The seed is threaded into torch and into persistent RNGs on the
  policy network and trainer instead of allocating a fresh RNG per action.
- `Target.send_probe` now backs off exponentially between retries, retries on
  HTTP 429, and honors a numeric `Retry-After` header.
- Non-JSON success responses from a target now raise a `TargetResponseError`
  with context instead of a bare `JSONDecodeError`.
- A failed probe inside `send_conversation_turn` no longer leaves a dangling
  attacker turn in the conversation history.

### Removed

- Deleted the duplicate top-level `atlas_data/techniques.json`; the taxonomy is
  shipped as package data at `infiltr/atlas/data/techniques.json`.

### Packaging / CI

- Ship a `py.typed` marker so downstream type checkers see inline types.
- CI now tests Python 3.11/3.12/3.13, type-checks in strict mode, and has a
  build + wheel-install smoke job.
- Added a tag-triggered release workflow using PyPI trusted publishing.
- Added a composite GitHub Action (`action.yml`) that installs infiltr and runs
  a scan plus SARIF report.
