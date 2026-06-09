from __future__ import annotations

from pathlib import Path
from typing import Any

from hipaa_audit.devices import assess_devices
from hipaa_audit.models import CheckResult, CheckStatus


def run(
    check: dict[str, Any],
    *,
    repo_path: Path,
    config: dict[str, Any],
    evidence_dir: Path,
) -> CheckResult:
    dev_cfg = config.get("devices", {})
    if not dev_cfg.get("enabled", False):
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.SKIP,
            message="Device checks disabled — set devices.enabled: true",
        )

    path = repo_path / dev_cfg.get("register_path", "compliance/devices.yaml")
    handler = check.get("handler", "device_inventory_compliant")
    if handler == "device_inventory_compliant":
        tier, message, issues = assess_devices(path, config)
        if tier == "pass":
            return CheckResult(check_id=check["id"], title=check.get("title", check["id"]), status=CheckStatus.PASS, message=message)
        if tier == "manual":
            return CheckResult(
                check_id=check["id"],
                title=check.get("title", check["id"]),
                status=CheckStatus.MANUAL,
                message=message,
                remediation="hipaa-audit devices import <jamf-or-intune.csv>",
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
        message=f"Unknown devices handler: {handler}",
    )
