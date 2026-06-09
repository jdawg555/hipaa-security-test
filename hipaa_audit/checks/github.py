from __future__ import annotations

import json
import os
import subprocess
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
    gh_config = config.get("github", {})
    if not gh_config.get("enabled", False):
        return CheckResult(
            check_id=check_id,
            title=title,
            status=CheckStatus.SKIP,
            message="GitHub checks disabled — set github.enabled: true in hipaa-audit.yaml",
        )
    handler = check.get("handler", check_id)
    handlers = {
        "branch_protection": _branch_protection,
        "secret_scanning": _secret_scanning,
        "dependabot": _dependabot,
    }
    fn = handlers.get(handler)
    if fn is None:
        return CheckResult(
            check_id=check_id,
            title=title,
            status=CheckStatus.ERROR,
            message=f"Unknown GitHub handler: {handler}",
        )
    return fn(check, repo_path=repo_path, config=gh_config, evidence_dir=evidence_dir)


def _gh_api(path: str) -> dict | list | None:
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not token:
        try:
            out = subprocess.run(
                ["gh", "api", path],
                capture_output=True,
                text=True,
                check=True,
                timeout=30,
            )
            return json.loads(out.stdout)
        except (subprocess.CalledProcessError, FileNotFoundError, json.JSONDecodeError):
            return None
    import urllib.request

    req = urllib.request.Request(
        f"https://api.github.com{path}",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
            return json.loads(resp.read().decode())
    except Exception:
        return None


def _repo_slug(repo_path, config) -> str | None:
    if config.get("repo"):
        return config["repo"]
    try:
        out = subprocess.run(
            ["git", "-C", str(repo_path), "remote", "get-url", "origin"],
            capture_output=True,
            text=True,
            check=True,
        )
        url = out.stdout.strip()
        if "github.com" in url:
            parts = url.rstrip(".git").split("github.com/")[-1].split("/")
            if len(parts) >= 2:
                return f"{parts[-2]}/{parts[-1]}"
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    return None


def _branch_protection(check, *, repo_path, config, evidence_dir) -> CheckResult:
    slug = _repo_slug(repo_path, config)
    if not slug:
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.SKIP,
            message="Could not detect GitHub repo — set github.repo in config",
        )
    branch = config.get("default_branch", "main")
    data = _gh_api(f"/repos/{slug}/branches/{branch}/protection")
    evidence = evidence_dir / "github-branch-protection.json"
    evidence.write_text(json.dumps(data or {}, indent=2))
    if data and data.get("required_status_checks"):
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
        message=f"No branch protection on {branch}",
        evidence_path=str(evidence),
        remediation="Enable required status checks and PR reviews on main",
    )


def _secret_scanning(check, *, repo_path, config, evidence_dir) -> CheckResult:
    slug = _repo_slug(repo_path, config)
    if not slug:
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.SKIP,
            message="Could not detect GitHub repo",
        )
    data = _gh_api(f"/repos/{slug}")
    evidence = evidence_dir / "github-repo-security.json"
    evidence.write_text(json.dumps(data or {}, indent=2))
    if data and data.get("security_and_analysis", {}).get("secret_scanning", {}).get("status") == "enabled":
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.PASS,
            message="GitHub secret scanning enabled",
            evidence_path=str(evidence),
        )
    return CheckResult(
        check_id=check["id"],
        title=check.get("title", check["id"]),
        status=CheckStatus.WARN,
        message="Secret scanning not confirmed enabled",
        evidence_path=str(evidence),
        remediation="Enable GitHub Advanced Security or secret scanning",
    )


def _dependabot(check, *, repo_path, config, evidence_dir) -> CheckResult:
    dependabot = repo_path / ".github" / "dependabot.yml"
    if dependabot.exists():
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.PASS,
            message="Dependabot configuration present",
            evidence_path=str(dependabot),
        )
    return CheckResult(
        check_id=check["id"],
        title=check.get("title", check["id"]),
        status=CheckStatus.WARN,
        message="No .github/dependabot.yml",
        remediation="Add Dependabot for dependency vulnerability alerts",
    )
