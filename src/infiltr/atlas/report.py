"""Report generation for ATLAS-mapped findings."""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from jinja2 import BaseLoader, Environment

from infiltr.atlas.baseline import (
    BaselineComparison,
    compare_findings,
    finding_fingerprint,
)
from infiltr.atlas.taxonomy import ATLASTaxonomy
from infiltr.exceptions import ReportGenerationError
from infiltr.logging import get_logger
from infiltr.models import Finding, Severity

if TYPE_CHECKING:
    from infiltr.redteam import RedTeamResults

logger = get_logger("infiltr.atlas.report")

_SEVERITY_RANK = {severity: idx for idx, severity in enumerate(Severity)}

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>infiltr Security Assessment</title>
  <style>
    :root { --bg: #0d1117; --fg: #c9d1d9; --accent: #58a6ff;
            --critical: #f85149; --high: #d29922; --medium: #e3b341;
            --low: #3fb950; --card-bg: #161b22; --border: #30363d; }
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI',
           Helvetica, Arial, sans-serif; background: var(--bg);
           color: var(--fg); line-height: 1.6; padding: 2rem; }
    .container { max-width: 1200px; margin: 0 auto; }
    h1 { color: var(--accent); margin-bottom: 0.5rem; font-size: 2rem; }
    .subtitle { color: #8b949e; margin-bottom: 2rem; }
    .summary { display: grid; grid-template-columns: repeat(auto-fit,
               minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
    .stat-card { background: var(--card-bg); border: 1px solid var(--border);
                 border-radius: 8px; padding: 1.5rem; text-align: center; }
    .stat-value { font-size: 2.5rem; font-weight: 700; }
    .stat-label { color: #8b949e; font-size: 0.875rem; text-transform: uppercase; }
    .critical { color: var(--critical); }
    .high { color: var(--high); }
    .medium { color: var(--medium); }
    .low { color: var(--low); }
    .finding { background: var(--card-bg); border: 1px solid var(--border);
               border-radius: 8px; padding: 1.5rem; margin-bottom: 1rem; }
    .finding-header { display: flex; justify-content: space-between;
                      align-items: center; margin-bottom: 1rem; }
    .finding-title { font-size: 1.125rem; font-weight: 600; }
    .badge { padding: 0.25rem 0.75rem; border-radius: 999px;
             font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }
    .badge-critical { background: #f8514922; color: var(--critical); }
    .badge-high { background: #d2992222; color: var(--high); }
    .badge-medium { background: #e3b34122; color: var(--medium); }
    .badge-low { background: #3fb95022; color: var(--low); }
    .detail { margin-bottom: 0.75rem; }
    .detail-label { color: #8b949e; font-size: 0.8rem; text-transform: uppercase;
                    margin-bottom: 0.25rem; }
    pre { background: #0d1117; border: 1px solid var(--border); border-radius: 4px;
          padding: 1rem; overflow-x: auto; font-size: 0.85rem; }
    h2 { font-size: 1.25rem; margin: 2rem 0 0.25rem; }
    .section-note { color: #8b949e; font-size: 0.85rem; margin-bottom: 1rem; }
    .matrix { display: grid; grid-auto-flow: column;
              grid-auto-columns: minmax(150px, 1fr); gap: 0.5rem;
              overflow-x: auto; padding-bottom: 0.5rem; }
    .matrix-col { display: flex; flex-direction: column; gap: 0.35rem; }
    .matrix-tactic { font-size: 0.75rem; font-weight: 600; text-transform: uppercase;
                     color: #8b949e; padding: 0.25rem 0; min-height: 2.5rem; }
    .matrix-cell { font: inherit; font-size: 0.78rem; text-align: left;
                   line-height: 1.3; padding: 0.45rem 0.5rem; border-radius: 6px;
                   border: 1px solid var(--border); background: var(--card-bg);
                   color: #8b949e; }
    .matrix-cell .cell-id { display: block; font-size: 0.7rem; opacity: 0.8; }
    .matrix-cell .cell-count { float: right; font-weight: 700; }
    button.matrix-cell { cursor: pointer; color: #0d1117; border-color: transparent; }
    button.matrix-cell:hover, button.matrix-cell:focus-visible {
      outline: 2px solid var(--accent); outline-offset: 1px; }
    button.matrix-cell[aria-pressed="true"] { outline: 2px solid var(--fg); }
    .heat-critical { background: var(--critical); }
    .heat-high { background: var(--high); }
    .heat-medium { background: var(--medium); }
    .heat-low { background: var(--low); }
    .heat-info { background: var(--accent); }
    .legend { display: flex; flex-wrap: wrap; gap: 0.75rem; font-size: 0.8rem;
              color: #8b949e; margin: 0.5rem 0 1rem; }
    .legend i { display: inline-block; width: 0.8rem; height: 0.8rem;
                border-radius: 3px; margin-right: 0.3rem; vertical-align: -1px; }
    .filter-bar { display: flex; gap: 1rem; align-items: center;
                  margin-bottom: 1rem; color: #8b949e; }
    .filter-bar button { font: inherit; background: none; color: var(--accent);
                         border: 1px solid var(--border); border-radius: 6px;
                         padding: 0.2rem 0.6rem; cursor: pointer; }
    [hidden] { display: none !important; }
    .footer { margin-top: 2rem; padding-top: 1rem; border-top: 1px solid
              var(--border); color: #8b949e; font-size: 0.8rem; text-align: center; }
  </style>
</head>
<body>
  <div class="container">
    <h1>infiltr Security Assessment</h1>
    <p class="subtitle">Generated {{ timestamp }} | {{ total_findings }} findings</p>
    <div class="summary">
      <div class="stat-card">
        <div class="stat-value critical">{{ critical_count }}</div>
        <div class="stat-label">Critical</div>
      </div>
      <div class="stat-card">
        <div class="stat-value high">{{ high_count }}</div>
        <div class="stat-label">High</div>
      </div>
      <div class="stat-card">
        <div class="stat-value medium">{{ medium_count }}</div>
        <div class="stat-label">Medium</div>
      </div>
      <div class="stat-card">
        <div class="stat-value low">{{ low_count }}</div>
        <div class="stat-label">Low</div>
      </div>
      <div class="stat-card">
        <div class="stat-value" style="color: var(--accent);">{{ total_probes }}</div>
        <div class="stat-label">Total Probes</div>
      </div>
    </div>
    <h2>MITRE ATLAS Coverage</h2>
    <p class="section-note">
      Techniques in the bundled MITRE ATLAS {{ atlas_version }} taxonomy, grouped by
      tactic and colored by the highest-severity finding. Select a highlighted
      technique to show only its findings.
      {% if unmapped_count %}{{ unmapped_count }} finding(s) use technique IDs outside
      the bundled taxonomy and are listed below only.{% endif %}
    </p>
    <div class="legend">
      <span><i class="heat-critical"></i>Critical</span>
      <span><i class="heat-high"></i>High</span>
      <span><i class="heat-medium"></i>Medium</span>
      <span><i class="heat-low"></i>Low</span>
      <span><i class="heat-info"></i>Info</span>
      <span><i style="border: 1px solid var(--border);"></i>No finding</span>
    </div>
    <div class="matrix" role="group" aria-label="ATLAS technique matrix">
      {% for column in matrix %}
      <div class="matrix-col">
        <div class="matrix-tactic" title="{{ column.tactic_id }}">{{ column.tactic }}</div>
        {% for cell in column.cells %}
        {% if cell.count %}
        <button type="button" class="matrix-cell heat-{{ cell.severity }}"
                data-technique="{{ cell.id }}" aria-pressed="false"
                title="{{ cell.id }} {{ cell.name }}: {{ cell.count }} finding(s), highest {{ cell.severity | upper }} ({{ cell.ids | join(', ') }})">
          <span class="cell-count">{{ cell.count }}</span>
          <span class="cell-id">{{ cell.id }}</span>{{ cell.name }}
        </button>
        {% else %}
        <div class="matrix-cell" title="{{ cell.id }} {{ cell.name }}: no findings">
          <span class="cell-id">{{ cell.id }}</span>{{ cell.name }}
        </div>
        {% endif %}
        {% endfor %}
      </div>
      {% endfor %}
    </div>
    <h2 id="findings">Findings</h2>
    <div class="filter-bar" id="matrix-filter" hidden>
      <span>Showing findings for <strong id="matrix-filter-id"></strong></span>
      <button type="button" id="matrix-reset">Show all findings</button>
    </div>
    {% for row in finding_rows %}
    {% set finding = row.finding %}
    <div class="finding" data-technique="{{ row.technique }}">
      <div class="finding-header">
        <div class="finding-title">{{ finding.technique_id }} &mdash; {{ finding.technique_name }}</div>
        <span class="badge badge-{{ finding.severity.value | lower }}">{{ finding.severity.value }}</span>
      </div>
      <div class="detail">
        <div class="detail-label">Tactic</div>
        <div>{{ finding.tactic }}</div>
      </div>
      <div class="detail">
        <div class="detail-label">Category</div>
        <div>{{ finding.category.value }}</div>
      </div>
      <div class="detail">
        <div class="detail-label">Reproducibility</div>
        <div>{{ (finding.reproducibility * 100) | round(1) }}%</div>
      </div>
      <div class="detail">
        <div class="detail-label">Attack Prompt</div>
        <pre>{{ finding.attack_prompt | e }}</pre>
      </div>
      <div class="detail">
        <div class="detail-label">Target Response</div>
        <pre>{{ finding.response | e }}</pre>
      </div>
      <div class="detail">
        <div class="detail-label">Remediation</div>
        <div>{{ finding.remediation }}</div>
      </div>
    </div>
    {% endfor %}
    <div class="footer">
      infiltr v{{ version }} &mdash; RL-based adversarial red-team agent for LLM systems
      &mdash; mapped to MITRE ATLAS {{ atlas_version }}
    </div>
  </div>
  <script>
  (function () {
    var cells = document.querySelectorAll("button.matrix-cell");
    var findings = document.querySelectorAll(".finding");
    var bar = document.getElementById("matrix-filter");
    var label = document.getElementById("matrix-filter-id");
    var active = null;
    function show(id) {
      active = id;
      findings.forEach(function (f) {
        f.hidden = id !== null && f.getAttribute("data-technique") !== id;
      });
      cells.forEach(function (c) {
        c.setAttribute("aria-pressed", String(c.getAttribute("data-technique") === id));
      });
      bar.hidden = id === null;
      label.textContent = id || "";
    }
    cells.forEach(function (c) {
      c.addEventListener("click", function () {
        var id = c.getAttribute("data-technique");
        show(active === id ? null : id);
        if (active) { document.getElementById("findings").scrollIntoView(); }
      });
    });
    document.getElementById("matrix-reset").addEventListener("click", function () {
      show(null);
    });
  })();
  </script>
</body>
</html>
"""


class ATLASReport:
    """Generate structured reports from red-team assessment results.

    Supports JSON, HTML, and SARIF output formats for integration
    with CI/CD pipelines, stakeholder reporting, and GitHub Security.

    Args:
        results: A RedTeamResults instance, or a list of Finding objects.
        taxonomy: ATLAS taxonomy used for the HTML coverage matrix and the
            ATLAS version stamp. Defaults to the bundled taxonomy.
    """

    def __init__(
        self,
        results: RedTeamResults | list[Finding] | dict[str, Any],
        taxonomy: ATLASTaxonomy | None = None,
    ) -> None:
        self._taxonomy = taxonomy
        if isinstance(results, list):
            self._findings = results
            self._summary: dict[str, Any] = {}
            self._total_probes = len(results)
            self._novel_count = 0
        elif isinstance(results, dict):
            findings_data = results.get("findings") or []
            self._findings = [
                finding
                if isinstance(finding, Finding)
                else _finding_from_mapping(finding)
                for finding in findings_data
            ]
            self._summary = dict(results.get("summary") or {})
            total_probes = self._summary.get("total_probes", len(self._findings))
            novel_attacks = self._summary.get(
                "novel_attacks",
                self._summary.get("novel_attack_count", 0),
            )
            self._total_probes = _coerce_summary_count(
                total_probes,
                default=len(self._findings),
            )
            self._novel_count = _coerce_summary_count(novel_attacks, default=0)
        else:
            self._findings = results.findings
            self._summary = {
                "total_probes": results.total_probes,
                "total_bypasses": results.total_bypasses,
                "novel_attacks": results.novel_attack_count,
                "training_stats": results.training_stats,
            }
            self._total_probes = results.total_probes
            self._novel_count = results.novel_attack_count

    @property
    def taxonomy(self) -> ATLASTaxonomy:
        """Return the ATLAS taxonomy, loading the bundled one on first use."""
        if self._taxonomy is None:
            self._taxonomy = ATLASTaxonomy()
        return self._taxonomy

    @property
    def findings(self) -> list[Finding]:
        """Return the list of findings."""
        return self._findings

    def compare_to(self, baseline: ATLASReport | list[Finding]) -> BaselineComparison:
        """Compare this report's findings against a baseline report."""
        baseline_findings = (
            baseline.findings if isinstance(baseline, ATLASReport) else baseline
        )
        return compare_findings(self._findings, baseline_findings)

    def with_findings(
        self,
        findings: list[Finding],
        *,
        summary_updates: dict[str, Any] | None = None,
    ) -> ATLASReport:
        """Return a report carrying the same summary but a different finding list."""
        report = ATLASReport(findings, taxonomy=self._taxonomy)
        report._summary = dict(self._summary)
        if summary_updates:
            report._summary.update(summary_updates)
        report._total_probes = self._total_probes
        report._novel_count = self._novel_count
        return report

    def count_by_severity(self, severity: str | Severity) -> int:
        """Count findings at a given severity level.

        Args:
            severity: Severity level string or enum value.

        Returns:
            Number of findings at that severity.
        """
        if isinstance(severity, str):
            severity = Severity(severity.upper())
        return sum(1 for f in self._findings if f.severity == severity)

    def to_json(self, path: str | Path) -> None:
        """Export findings as a JSON file.

        Args:
            path: Output file path.

        Raises:
            ReportGenerationError: If the file cannot be written.
        """
        try:
            summary = dict(self._summary)
            summary.update(
                {
                    "total_findings": len(self._findings),
                    "total_probes": self._total_probes,
                    "novel_attacks": self._novel_count,
                    "by_severity": {
                        s.value: self.count_by_severity(s) for s in Severity
                    },
                }
            )
            data = {
                "infiltr_version": _tool_version(),
                "atlas_version": self.taxonomy.version,
                "generated_at": datetime.now(UTC).isoformat(),
                "summary": summary,
                "findings": [_finding_to_dict(f) for f in self._findings],
            }
            Path(path).write_text(
                json.dumps(data, indent=2, default=str),
                encoding="utf-8",
            )
            logger.info("report_generated", format="json", path=str(path))
        except OSError as exc:
            raise ReportGenerationError("JSON", str(exc)) from exc

    def to_html(self, path: str | Path) -> None:
        """Export findings as an HTML report.

        Args:
            path: Output file path.

        Raises:
            ReportGenerationError: If the file cannot be written.
        """
        try:
            env = Environment(
                loader=BaseLoader(),
                autoescape=True,
            )
            template = env.from_string(_HTML_TEMPLATE)
            matrix, finding_rows, unmapped_count = _coverage_matrix(
                self._findings, self.taxonomy
            )

            html = template.render(
                matrix=matrix,
                finding_rows=finding_rows,
                unmapped_count=unmapped_count,
                atlas_version=self.taxonomy.version,
                timestamp=datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
                total_findings=len(self._findings),
                total_probes=self._total_probes,
                critical_count=self.count_by_severity(Severity.CRITICAL),
                high_count=self.count_by_severity(Severity.HIGH),
                medium_count=self.count_by_severity(Severity.MEDIUM),
                low_count=self.count_by_severity(Severity.LOW),
                version=_tool_version(),
            )

            Path(path).write_text(html, encoding="utf-8")
            logger.info("report_generated", format="html", path=str(path))
        except OSError as exc:
            raise ReportGenerationError("HTML", str(exc)) from exc

    def to_sarif(self, path: str | Path) -> None:
        """Export findings in SARIF format for GitHub Security integration.

        Args:
            path: Output file path.

        Raises:
            ReportGenerationError: If the file cannot be written.
        """
        try:
            rules: list[dict[str, Any]] = []
            results: list[dict[str, Any]] = []

            severity_to_sarif = {
                Severity.CRITICAL: "error",
                Severity.HIGH: "error",
                Severity.MEDIUM: "warning",
                Severity.LOW: "note",
                Severity.INFO: "note",
            }

            seen_rules: set[str] = set()

            for finding in self._findings:
                rule_id = finding.technique_id.replace(".", "_")

                if rule_id not in seen_rules:
                    seen_rules.add(rule_id)
                    rules.append(
                        {
                            "id": rule_id,
                            "name": finding.technique_name,
                            "shortDescription": {"text": finding.technique_name},
                            "fullDescription": {"text": finding.remediation},
                            "helpUri": (
                                "https://atlas.mitre.org/techniques/"
                                f"{finding.technique_id}"
                            ),
                            "defaultConfiguration": {
                                "level": severity_to_sarif[finding.severity]
                            },
                            "properties": {
                                "tags": [
                                    "security",
                                    "llm",
                                    finding.tactic.lower().replace(" ", "-"),
                                ],
                            },
                        }
                    )

                results.append(
                    {
                        "ruleId": rule_id,
                        "level": severity_to_sarif[finding.severity],
                        "message": {
                            "text": (
                                f"{finding.technique_name} vulnerability "
                                f"detected with "
                                f"{finding.reproducibility:.0%} "
                                f"reproducibility. "
                                f"Category: {finding.category.value}."
                            )
                        },
                        "properties": {
                            "fingerprint": finding_fingerprint(finding),
                            "attack_prompt": finding.attack_prompt[:500],
                            "response_preview": finding.response[:500],
                            "reproducibility": finding.reproducibility,
                        },
                    }
                )

            sarif = {
                "$schema": (
                    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
                    "main/sarif-2.1/schema/sarif-schema-2.1.0.json"
                ),
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {
                            "driver": {
                                "name": "infiltr",
                                "version": _tool_version(),
                                "informationUri": (
                                    "https://github.com/sushaan-k/infiltr"
                                ),
                                "rules": rules,
                            }
                        },
                        "results": results,
                    }
                ],
            }

            Path(path).write_text(
                json.dumps(sarif, indent=2),
                encoding="utf-8",
            )
            logger.info("report_generated", format="sarif", path=str(path))
        except OSError as exc:
            raise ReportGenerationError("SARIF", str(exc)) from exc

    def upload_to_github(
        self,
        repo: str | None = None,
        ref: str | None = None,
    ) -> bool:
        """Upload SARIF results to GitHub via the ``gh`` CLI.

        Generates a temporary SARIF file and invokes
        ``gh api`` to upload it.  If the ``gh`` CLI is not
        installed the method is a silent no-op and returns ``False``.

        Args:
            repo: GitHub repository in ``owner/repo`` format.
                If *None* the CLI auto-detects from the local git
                remote.
            ref: Git ref (branch/tag/SHA) for the upload.
                If *None* the CLI auto-detects from HEAD.

        Returns:
            ``True`` if the upload succeeded, ``False`` otherwise.
        """
        if shutil.which("gh") is None:
            logger.info("gh_cli_not_found", action="skip_upload")
            return False

        tmpdir = tempfile.mkdtemp(prefix="infiltr_sarif_")
        sarif_path = Path(tmpdir) / "infiltr-results.sarif"
        try:
            self.to_sarif(sarif_path)
        except ReportGenerationError:
            logger.warning("sarif_generation_failed_for_upload")
            return False

        cmd: list[str] = [
            "gh",
            "api",
            "-X",
            "POST",
            "-H",
            "Accept: application/vnd.github+json",
        ]
        endpoint = "/repos/{repo}/code-scanning/sarifs"
        if repo is not None:
            endpoint = endpoint.replace("{repo}", repo)
        else:
            endpoint = endpoint.replace("{repo}", "{owner}/{repo}")
        cmd.extend([endpoint])

        if ref is not None:
            cmd.extend(["-f", f"ref={ref}"])

        cmd.extend(["-f", f"sarif=@{sarif_path}"])

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0:
                logger.info(
                    "sarif_uploaded",
                    repo=repo or "auto",
                )
                return True
            logger.warning(
                "sarif_upload_failed",
                returncode=result.returncode,
                stderr=result.stderr[:200],
            )
            return False
        except (subprocess.TimeoutExpired, OSError) as exc:
            logger.warning("sarif_upload_error", error=str(exc))
            return False

    def to_dict(self) -> dict[str, Any]:
        """Export findings as a Python dictionary.

        Returns:
            A dictionary with summary and findings data.
        """
        summary = dict(self._summary)
        summary.update(
            {
                "total_findings": len(self._findings),
                "total_probes": self._total_probes,
                "novel_attacks": self._novel_count,
                "by_severity": {s.value: self.count_by_severity(s) for s in Severity},
            }
        )
        return {
            "summary": summary,
            "findings": [_finding_to_dict(f) for f in self._findings],
        }


def _coverage_matrix(
    findings: list[Finding],
    taxonomy: ATLASTaxonomy,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], int]:
    """Group findings onto the ATLAS tactic/technique matrix.

    Each finding is attributed to its top-level technique (a sub-technique
    finding counts toward its parent). A technique appears under every tactic
    it belongs to, as on the ATLAS matrix.

    Returns:
        The matrix columns, per-finding rows carrying the attributed
        technique ID, and the number of findings outside the taxonomy.
    """
    by_technique: dict[str, list[Finding]] = {}
    rows: list[dict[str, Any]] = []
    unmapped = 0
    for finding in findings:
        technique = taxonomy.get_technique(finding.technique_id)
        if technique is None:
            parent_id = ".".join(finding.technique_id.split(".")[:2])
            technique = taxonomy.get_technique(parent_id)
        if technique is None:
            unmapped += 1
            rows.append({"finding": finding, "technique": finding.technique_id})
            continue
        by_technique.setdefault(technique.id, []).append(finding)
        rows.append({"finding": finding, "technique": technique.id})

    columns: list[dict[str, Any]] = []
    for tactic in taxonomy.tactics:
        cells = []
        for technique in taxonomy.techniques:
            if tactic.name not in technique.tactics:
                continue
            hits = by_technique.get(technique.id, [])
            worst = (
                min(hits, key=lambda f: _SEVERITY_RANK[f.severity]) if hits else None
            )
            cells.append(
                {
                    "id": technique.id,
                    "name": technique.name,
                    "count": len(hits),
                    "severity": worst.severity.value.lower() if worst else "none",
                    "ids": sorted({f.technique_id for f in hits}),
                }
            )
        columns.append({"tactic": tactic.name, "tactic_id": tactic.id, "cells": cells})
    return columns, rows, unmapped


def _tool_version() -> str:
    """Return the installed infiltr version (imported lazily to avoid a cycle)."""
    from infiltr import __version__

    return __version__


def _finding_from_mapping(data: object) -> Finding:
    """Build a Finding while preserving exported fingerprints in metadata."""
    if not isinstance(data, dict):
        return Finding.model_validate(data)

    payload = dict(data)
    fingerprint = payload.pop("fingerprint", None)
    if fingerprint is not None:
        metadata = dict(payload.get("metadata") or {})
        metadata.setdefault("fingerprint", fingerprint)
        payload["metadata"] = metadata
    return Finding(**payload)


def _finding_to_dict(finding: Finding) -> dict[str, Any]:
    """Serialize a finding with the stable baseline fingerprint included."""
    data: dict[str, Any] = json.loads(finding.model_dump_json())
    data["fingerprint"] = finding_fingerprint(finding)
    return data


def _coerce_summary_count(value: object, *, default: int) -> int:
    """Normalize summary counters from JSON-like inputs into integers."""
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return default
    return default
