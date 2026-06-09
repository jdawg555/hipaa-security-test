from __future__ import annotations

from pathlib import Path
from typing import Any

from hipaa_audit.apps import assess_inventory
from hipaa_audit.models import CheckResult, CheckStatus


def run(
    check: dict[str, Any],
    *,
    repo_path: Path,
    config: dict[str, Any],
    evidence_dir: Path,
) -> CheckResult:
    saas_cfg = config.get("saas_inventory", {})
    if not saas_cfg.get("enabled", False):
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.SKIP,
            message="SaaS inventory disabled — set saas_inventory.enabled: true",
        )

    inventory = repo_path / saas_cfg.get("register_path", "compliance/saas-inventory.yaml")
    vendors = repo_path / config.get("vendors", {}).get("register_path", "compliance/vendors.yaml")
    handler = check.get("handler", "saas_inventory_tracked")
    if handler == "saas_inventory_tracked":
        tier, message, issues = assess_inventory(inventory, vendors, config)
        if tier == "pass":
            return CheckResult(check_id=check["id"], title=check.get("title", check["id"]), status=CheckStatus.PASS, message=message)
        if tier == "manual":
            return CheckResult(
                check_id=check["id"],
                title=check.get("title", check["id"]),
                status=CheckStatus.MANUAL,
                message=message,
                remediation="hipaa-audit apps discover",
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
        message=f"Unknown apps handler: {handler}",
    )
