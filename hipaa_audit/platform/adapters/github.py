from __future__ import annotations

import os
import subprocess
from typing import Any

from hipaa_audit.platform.adapters.base import ConnectionResult, IntegrationAdapter


class GithubAdapter(IntegrationAdapter):
    id = "github"
    name = "GitHub"

    def test_connection(self, config: dict[str, Any]) -> ConnectionResult:
        gh = config.get("github", {})
        if not gh.get("enabled", False):
            return ConnectionResult(False, "GitHub integration is disabled — enable it first")
        repo = gh.get("repo", "")
        token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
        if not token:
            try:
                out = subprocess.run(
                    ["gh", "auth", "status"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                if out.returncode != 0:
                    return ConnectionResult(False, "Set GITHUB_TOKEN or authenticate with gh CLI")
            except (FileNotFoundError, subprocess.TimeoutExpired):
                return ConnectionResult(False, "Set GITHUB_TOKEN environment variable")
        if repo:
            try:
                if token:
                    import urllib.request

                    req = urllib.request.Request(
                        f"https://api.github.com/repos/{repo}",
                        headers={
                            "Authorization": f"Bearer {token}",
                            "Accept": "application/vnd.github+json",
                        },
                    )
                    with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310
                        if resp.status == 200:
                            return ConnectionResult(True, f"Connected to repository {repo}")
                else:
                    out = subprocess.run(
                        ["gh", "api", f"repos/{repo}"],
                        capture_output=True,
                        text=True,
                        timeout=15,
                        check=False,
                    )
                    if out.returncode == 0:
                        return ConnectionResult(True, f"Connected to repository {repo}")
                    return ConnectionResult(False, f"Cannot access repo {repo}: {out.stderr[:120]}")
            except Exception as exc:  # noqa: BLE001
                return ConnectionResult(False, f"GitHub repo check failed: {exc}")
        return ConnectionResult(True, "GitHub token available — set repo slug in Settings for repo checks")
