from __future__ import annotations

from pathlib import Path
from typing import Any

from hipaa_audit.models import CheckResult, CheckStatus
from hipaa_audit.questionnaires import assess_questionnaires


def run(
    check: dict[str, Any],
    *,
    repo_path: Path,
    config: dict[str, Any],
    evidence_dir: Path,
) -> CheckResult:
    v_cfg = config.get("vendors", {})
    if not v_cfg.get("enabled", False):
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.SKIP,
            message="Vendor questionnaire checks disabled",
        )

    q_path = repo_path / v_cfg.get("questionnaires_path", "compliance/vendor-questionnaires.yaml")
    handler = check.get("handler", "vendor_questionnaires_current")
    if handler == "vendor_questionnaires_current":
        tier, message, issues = assess_questionnaires(q_path, config)
        if tier == "pass":
            return CheckResult(check_id=check["id"], title=check.get("title", check["id"]), status=CheckStatus.PASS, message=message)
        if tier == "manual":
            return CheckResult(
                check_id=check["id"],
                title=check.get("title", check["id"]),
                status=CheckStatus.MANUAL,
                message=message,
                remediation="hipaa-audit vendor send VND-001 vendor@example.com",
            )
        status = CheckStatus.WARN if tier == "warn" else CheckStatus.FAIL
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=status,
            message=message,
        )
    return CheckResult(
        check_id=check["id"],
        title=check.get("title", check["id"]),
        status=CheckStatus.ERROR,
        message=f"Unknown questionnaire handler: {handler}",
    )
