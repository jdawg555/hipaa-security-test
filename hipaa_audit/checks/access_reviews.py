from __future__ import annotations

from pathlib import Path
from typing import Any

from hipaa_audit.access_reviews import assess_access_reviews
from hipaa_audit.models import CheckResult, CheckStatus


def run(
    check: dict[str, Any],
    *,
    repo_path: Path,
    config: dict[str, Any],
    evidence_dir: Path,
) -> CheckResult:
    ar_cfg = config.get("access_reviews", {})
    if not ar_cfg.get("enabled", False):
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.SKIP,
            message="Access review checks disabled — set access_reviews.enabled: true",
        )

    path = repo_path / ar_cfg.get("register_path", "compliance/access-reviews.yaml")
    handler = check.get("handler", "access_review_campaign")
    if handler == "access_review_campaign":
        tier, message, issues = assess_access_reviews(path, config)
        if tier == "pass":
            return CheckResult(check_id=check["id"], title=check.get("title", check["id"]), status=CheckStatus.PASS, message=message)
        if tier == "manual":
            return CheckResult(
                check_id=check["id"],
                title=check.get("title", check["id"]),
                status=CheckStatus.MANUAL,
                message=message,
                remediation="hipaa-audit access-review start",
            )
        status = CheckStatus.WARN if tier == "warn" else CheckStatus.FAIL
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=status,
            message=f"{message}" + (f": {', '.join(issues[:2])}" if issues else ""),
        )
    return CheckResult(
        check_id=check["id"],
        title=check.get("title", check["id"]),
        status=CheckStatus.ERROR,
        message=f"Unknown access review handler: {handler}",
    )
