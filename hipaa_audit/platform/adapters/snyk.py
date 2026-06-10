from __future__ import annotations

import json
import os
import urllib.request
from typing import Any

from hipaa_audit.platform.adapters.base import ConnectionResult, IntegrationAdapter


class SnykAdapter(IntegrationAdapter):
    id = "snyk"
    name = "Snyk"

    def test_connection(self, config: dict[str, Any]) -> ConnectionResult:
        snyk = config.get("integrations", {}).get("snyk", {})
        if not snyk.get("enabled", False):
            return ConnectionResult(False, "Snyk integration is disabled")
        token = os.environ.get(snyk.get("token_env", "SNYK_TOKEN"), "")
        if not token:
            return ConnectionResult(False, "Set SNYK_TOKEN or save token via connect wizard")
        org = snyk.get("org_id") or os.environ.get("SNYK_ORG_ID", "")
        url = "https://api.snyk.io/rest/orgs?version=2024-10-15"
        req = urllib.request.Request(
            url,
            headers={"Authorization": f"token {token}", "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:  # noqa: S310
                data = json.loads(resp.read().decode())
            orgs = data.get("data", [])
            if org and not any(o.get("id") == org for o in orgs):
                return ConnectionResult(False, f"Org {org} not found for token")
            return ConnectionResult(True, f"Snyk API connected ({len(orgs)} org(s))")
        except Exception as exc:  # noqa: BLE001
            return ConnectionResult(False, f"Snyk API failed: {exc}")
