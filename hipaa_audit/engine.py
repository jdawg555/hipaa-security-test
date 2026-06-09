from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from hipaa_audit.checks.base import run_check
from hipaa_audit.controls import load_controls
from hipaa_audit.models import AuditReport, CheckStatus, ControlResult


def run_audit(
    repo_path: Path,
    *,
    config: dict[str, Any],
    controls_path: Path | None = None,
    evidence_dir: Path | None = None,
    categories: list[str] | None = None,
) -> AuditReport:
    repo_path = repo_path.resolve()
    evidence = evidence_dir or (repo_path / "evidence" / datetime.now(UTC).strftime("%Y-%m-%d"))
    evidence.mkdir(parents=True, exist_ok=True)

    controls = load_controls(controls_path)
    if categories:
        controls = [c for c in controls if c.category in categories]

    results: list[ControlResult] = []
    for control in controls:
        check_results = []
        for check in control.checks:
            if check.get("type") == "manual":
                from hipaa_audit.models import CheckResult

                check_results.append(
                    CheckResult(
                        check_id=check["id"],
                        title=check.get("title", check["id"]),
                        status=CheckStatus.MANUAL,
                        message=check.get("instructions", "Manual attestation required"),
                        remediation=check.get("remediation"),
                    )
                )
            else:
                check_results.append(
                    run_check(check, repo_path=repo_path, config=config, evidence_dir=evidence)
                )
        results.append(ControlResult(control=control, results=check_results))

    return AuditReport(
        org_name=config.get("org_name", "Your Organization"),
        repo_path=str(repo_path),
        controls=results,
        generated_at=datetime.now(UTC).isoformat(),
        config=config,
    )
