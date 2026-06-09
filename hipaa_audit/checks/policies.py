from __future__ import annotations

from pathlib import Path
from typing import Any

from hipaa_audit.models import CheckResult, CheckStatus

REQUIRED_POLICIES = [
    ("hipaa-privacy-policy.md", "HIPAA Privacy Policy"),
    ("hipaa-security-policy.md", "HIPAA Security Policy"),
    ("access-control-policy.md", "Access Control Policy"),
    ("incident-response-plan.md", "Incident Response Plan"),
    ("breach-notification-plan.md", "Breach Notification Plan"),
    ("encryption-policy.md", "Encryption Policy"),
    ("vendor-management-policy.md", "Vendor Management Policy"),
    ("workforce-training-plan.md", "Workforce Training Plan"),
    ("risk-management-policy.md", "Risk Management Policy"),
    ("data-retention-policy.md", "Data Retention Policy"),
    ("acceptable-use-policy.md", "Acceptable Use Policy"),
    ("logging-audit-policy.md", "Logging & Audit Policy"),
]


def run(
    check: dict[str, Any],
    *,
    repo_path: Path,
    config: dict[str, Any],
    evidence_dir: Path,
) -> CheckResult:
    check_id = check["id"]
    title = check.get("title", check_id)
    handler = check.get("handler", "policy_library_complete")

    if handler == "policy_library_complete":
        return _policy_library(check, repo_path=repo_path, config=config)
    if handler == "policy_review_dates":
        return _policy_review_dates(check, repo_path=repo_path, config=config)
    return CheckResult(
        check_id=check_id,
        title=title,
        status=CheckStatus.ERROR,
        message=f"Unknown policies handler: {handler}",
    )


def _policy_dirs(repo_path: Path, config: dict[str, Any]) -> list[Path]:
    dirs = []
    for d in [
        config.get("policy_dir", "policies"),
        "compliance/policies",
        "docs/security/policies",
    ]:
        p = repo_path / d
        if p.is_dir():
            dirs.append(p)
    # Also check this tool's bundled policies when auditing itself
    bundled = Path(__file__).resolve().parent.parent.parent / "policies"
    if bundled.is_dir():
        dirs.append(bundled)
    return dirs


def _policy_library(check, *, repo_path, config) -> CheckResult:
    dirs = _policy_dirs(repo_path, config)
    found = []
    missing = []
    for filename, label in REQUIRED_POLICIES:
        if any((d / filename).exists() for d in dirs):
            found.append(label)
        else:
            missing.append(label)
    pct = int(100 * len(found) / len(REQUIRED_POLICIES))
    if not missing:
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.PASS,
            message=f"All {len(REQUIRED_POLICIES)} policy templates present",
        )
    if len(found) >= len(REQUIRED_POLICIES) // 2:
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.WARN,
            message=f"{pct}% policy library ({len(found)}/{len(REQUIRED_POLICIES)}). Missing: {', '.join(missing[:3])}...",
            remediation="Copy policies/ from hipaa-security-test and customize",
        )
    return CheckResult(
        check_id=check["id"],
        title=check.get("title", check["id"]),
        status=CheckStatus.FAIL,
        message=f"Only {len(found)}/{len(REQUIRED_POLICIES)} policies found",
        remediation="Initialize policy library from policies/ directory",
    )


def _policy_review_dates(check, *, repo_path, config) -> CheckResult:
    dirs = _policy_dirs(repo_path, config)
    stale = []
    for d in dirs:
        for path in d.glob("*.md"):
            text = path.read_text(errors="ignore")
            if "review cadence" not in text.lower() and "annual" not in text.lower():
                stale.append(path.name)
    if not stale:
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.PASS,
            message="Policies include review cadence language",
        )
    return CheckResult(
        check_id=check["id"],
        title=check.get("title", check["id"]),
        status=CheckStatus.MANUAL,
        message=f"Verify annual review for: {', '.join(stale[:5])}",
        remediation="Add review cadence and last-reviewed date to each policy",
    )
