from __future__ import annotations

import os
import urllib.parse
from typing import Any

from hipaa_audit.platform.adapters.base import ConnectionResult, IntegrationAdapter


class GitLabAdapter(IntegrationAdapter):
    id = "gitlab"
    name = "GitLab"

    def test_connection(self, config: dict[str, Any]) -> ConnectionResult:
        gl = config.get("gitlab", {})
        if not gl.get("enabled", False):
            return ConnectionResult(False, "GitLab integration is disabled — enable it first")
        token = os.environ.get("GITLAB_TOKEN", "")
        if not token:
            return ConnectionResult(False, "Set GITLAB_TOKEN environment variable or workspace secrets")
        project = gl.get("project", "")
        base = gl.get("base_url", "https://gitlab.com").rstrip("/")
        if not project:
            return ConnectionResult(True, "GitLab token set — add gitlab.project in Settings for repo checks")
        import urllib.request

        encoded = urllib.parse.quote(project, safe="")
        req = urllib.request.Request(
            f"{base}/api/v4/projects/{encoded}",
            headers={"PRIVATE-TOKEN": token, "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310
                if resp.status == 200:
                    return ConnectionResult(True, f"Connected to GitLab project {project}")
        except Exception as exc:  # noqa: BLE001
            return ConnectionResult(False, f"GitLab API failed: {exc}")
        return ConnectionResult(False, f"Cannot access GitLab project {project}")
