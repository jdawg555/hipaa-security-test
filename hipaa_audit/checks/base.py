from __future__ import annotations

from pathlib import Path
from typing import Any

from hipaa_audit.checks import (
    access_reviews,
    apps,
    aws,
    github,
    identity,
    integrations,
    personnel,
    policies,
    repo,
    vendors,
)
from hipaa_audit.models import CheckResult, CheckStatus

RUNNERS = {
    "repo": repo,
    "aws": aws,
    "github": github,
    "identity": identity,
    "personnel": personnel,
    "policies": policies,
    "integrations": integrations,
    "vendors": vendors,
    "access_reviews": access_reviews,
    "apps": apps,
}


def run_check(
    check: dict[str, Any],
    *,
    repo_path: Path,
    config: dict[str, Any],
    evidence_dir: Path,
) -> CheckResult:
    check_id = check["id"]
    title = check.get("title", check_id)
    module = check.get("module", "repo")
    runner = RUNNERS.get(module)
    if runner is None:
        return CheckResult(
            check_id=check_id,
            title=title,
            status=CheckStatus.ERROR,
            message=f"Unknown check module: {module}",
        )
    try:
        return runner.run(check, repo_path=repo_path, config=config, evidence_dir=evidence_dir)
    except Exception as exc:  # noqa: BLE001 — surface check failures in report
        return CheckResult(
            check_id=check_id,
            title=title,
            status=CheckStatus.ERROR,
            message=str(exc),
            remediation=check.get("remediation"),
        )
