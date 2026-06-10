from __future__ import annotations

import json
import os
import subprocess
import urllib.parse
from typing import Any

from hipaa_audit.models import CheckResult, CheckStatus


def run(
    check: dict[str, Any],
    *,
    repo_path,
    config: dict[str, Any],
    evidence_dir,
) -> CheckResult:
    check_id = check["id"]
    title = check.get("title", check_id)
    gl_config = config.get("gitlab", {})
    if not gl_config.get("enabled", False):
        return CheckResult(
            check_id=check_id,
            title=title,
            status=CheckStatus.SKIP,
            message="GitLab checks disabled — set gitlab.enabled: true in hipaa-audit.yaml",
        )
    handler = check.get("handler", check_id)
    handlers = {
        "branch_protection": _branch_protection,
        "secret_detection": _secret_detection,
        "dependency_scanning": _dependency_scanning,
    }
    fn = handlers.get(handler)
    if fn is None:
        return CheckResult(
            check_id=check_id,
            title=title,
            status=CheckStatus.ERROR,
            message=f"Unknown GitLab handler: {handler}",
        )
    return fn(check, repo_path=repo_path, config=gl_config, evidence_dir=evidence_dir)


def _gitlab_api(path: str, *, base_url: str) -> dict | list | None:
    token = os.environ.get("GITLAB_TOKEN", "")
    if not token:
        return None
    import urllib.request

    url = f"{base_url.rstrip('/')}/api/v4{path}"
    req = urllib.request.Request(
        url,
        headers={"PRIVATE-TOKEN": token, "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
            return json.loads(resp.read().decode())
    except Exception:
        return None


def _project_path(repo_path, config) -> str | None:
    if config.get("project"):
        return config["project"]
    try:
        out = subprocess.run(
            ["git", "-C", str(repo_path), "remote", "get-url", "origin"],
            capture_output=True,
            text=True,
            check=True,
        )
        url = out.stdout.strip()
        for marker in ("gitlab.com:", "gitlab.com/"):
            if marker in url:
                path = url.split(marker, 1)[-1].rstrip(".git")
                return path
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    return None


def _branch_protection(check, *, repo_path, config, evidence_dir) -> CheckResult:
    project = _project_path(repo_path, config)
    base = config.get("base_url", "https://gitlab.com")
    if not project:
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.SKIP,
            message="Could not detect GitLab project — set gitlab.project in config",
        )
    encoded = urllib.parse.quote(project, safe="")
    branch = config.get("default_branch", "main")
    data = _gitlab_api(f"/projects/{encoded}/protected_branches", base_url=base)
    evidence = evidence_dir / "gitlab-branch-protection.json"
    evidence.write_text(json.dumps(data or [], indent=2))
    protected = [b for b in (data or []) if b.get("name") == branch]
    if protected:
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.PASS,
            message=f"Branch protection on {branch}",
            evidence_path=str(evidence),
        )
    return CheckResult(
        check_id=check["id"],
        title=check.get("title", check["id"]),
        status=CheckStatus.FAIL,
        message=f"No protected branch rules for {branch}",
        evidence_path=str(evidence),
        remediation="Enable protected branch with merge request approvals on main",
    )


def _secret_detection(check, *, repo_path, config, evidence_dir) -> CheckResult:
    project = _project_path(repo_path, config)
    base = config.get("base_url", "https://gitlab.com")
    if not project:
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.SKIP,
            message="Could not detect GitLab project",
        )
    encoded = urllib.parse.quote(project, safe="")
    data = _gitlab_api(f"/projects/{encoded}", base_url=base)
    evidence = evidence_dir / "gitlab-project.json"
    evidence.write_text(json.dumps(data or {}, indent=2))
    if data and data.get("security_and_compliance_enabled"):
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.PASS,
            message="GitLab security and compliance features enabled",
            evidence_path=str(evidence),
        )
    return CheckResult(
        check_id=check["id"],
        title=check.get("title", check["id"]),
        status=CheckStatus.WARN,
        message="Secret detection / SAST not confirmed — enable Ultimate or secret detection",
        evidence_path=str(evidence),
        remediation="Enable GitLab secret detection or security scanning",
    )


def _dependency_scanning(check, *, repo_path, config, evidence_dir) -> CheckResult:
    ci = repo_path / ".gitlab-ci.yml"
    dependabot = repo_path / ".gitlab" / "dependabot.yml"
    if ci.exists() and "dependency_scanning" in ci.read_text():
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.PASS,
            message="GitLab dependency scanning referenced in CI",
            evidence_path=str(ci),
        )
    if dependabot.exists():
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.PASS,
            message="GitLab dependency scanning config present",
            evidence_path=str(dependabot),
        )
    return CheckResult(
        check_id=check["id"],
        title=check.get("title", check["id"]),
        status=CheckStatus.WARN,
        message="No GitLab dependency scanning in .gitlab-ci.yml",
        remediation="Add dependency_scanning or container_scanning to CI pipeline",
    )
