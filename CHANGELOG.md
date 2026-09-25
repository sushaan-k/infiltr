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
