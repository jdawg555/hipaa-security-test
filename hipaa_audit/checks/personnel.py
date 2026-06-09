from __future__ import annotations

from pathlib import Path
from typing import Any

from hipaa_audit.models import CheckResult, CheckStatus
from hipaa_audit.personnel import check_acknowledgments, check_training_csv


def run(
    check: dict[str, Any],
    *,
    repo_path: Path,
    config: dict[str, Any],
    evidence_dir: Path,
) -> CheckResult:
    check_id = check["id"]
    title = check.get("title", check_id)
    personnel = config.get("personnel", {})
    if not personnel.get("enabled", False):
        return CheckResult(
            check_id=check_id,
            title=title,
            status=CheckStatus.SKIP,
            message="Personnel checks disabled — set personnel.enabled: true",
        )

    handler = check.get("handler", check_id)
    if handler == "policy_acknowledgments":
        return _policy_acknowledgments(check, repo_path=repo_path, config=config)
    if handler == "training_csv_current":
        return _training_csv(check, repo_path=repo_path, config=config)
    return CheckResult(
        check_id=check_id,
        title=title,
        status=CheckStatus.ERROR,
        message=f"Unknown personnel handler: {handler}",
    )


def _policy_acknowledgments(check, *, repo_path, config) -> CheckResult:
    tier, _policies, gaps = check_acknowledgments(repo_path, config)
    if tier == "pass":
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.PASS,
            message="All required policies acknowledged by active workforce",
        )
    if tier == "missing":
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.MANUAL,
            message=gaps[0],
            remediation="Copy compliance/acknowledgments.example.yaml and record sign-offs",
        )
    status = CheckStatus.WARN if tier == "warn" else CheckStatus.FAIL
    return CheckResult(
        check_id=check["id"],
        title=check.get("title", check["id"]),
        status=status,
        message="; ".join(gaps[:5]),
        remediation="Collect annual policy acknowledgments from all workforce",
    )


def _training_csv(check, *, repo_path, config) -> CheckResult:
    tier, message, issues = check_training_csv(repo_path, config)
    if tier == "pass":
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.PASS,
            message=message,
        )
    if tier == "manual":
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.MANUAL,
            message=message,
            remediation="hipaa-audit import-training",
        )
    status = CheckStatus.WARN if tier == "warn" else CheckStatus.FAIL
    return CheckResult(
        check_id=check["id"],
        title=check.get("title", check["id"]),
        status=status,
        message=f"{message}: {', '.join(issues[:3])}",
    )
