from __future__ import annotations

from pathlib import Path
from typing import Any

from hipaa_audit.models import CheckResult, CheckStatus
from hipaa_audit.vendors import assess_vendors


def run(
    check: dict[str, Any],
    *,
    repo_path: Path,
    config: dict[str, Any],
    evidence_dir: Path,
) -> CheckResult:
    vendors_cfg = config.get("vendors", {})
    if not vendors_cfg.get("enabled", False):
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.SKIP,
            message="Vendor checks disabled — set vendors.enabled: true",
        )

    path = repo_path / vendors_cfg.get("register_path", "compliance/vendors.yaml")
    handler = check.get("handler", "vendor_register_current")
    if handler == "vendor_register_current":
        tier, message, issues = assess_vendors(path, config)
        if tier == "pass":
            return CheckResult(check_id=check["id"], title=check.get("title", check["id"]), status=CheckStatus.PASS, message=message)
        if tier == "manual":
            return CheckResult(
                check_id=check["id"],
                title=check.get("title", check["id"]),
                status=CheckStatus.MANUAL,
                message=message,
                remediation="hipaa-audit vendor init",
            )
        status = CheckStatus.WARN if tier == "warn" else CheckStatus.FAIL
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=status,
            message=f"{message}: {', '.join(issues[:3])}",
        )
    return CheckResult(
        check_id=check["id"],
        title=check.get("title", check["id"]),
        status=CheckStatus.ERROR,
        message=f"Unknown vendor handler: {handler}",
    )
