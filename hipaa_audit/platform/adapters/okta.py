from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any

from hipaa_audit.platform.adapters.base import ConnectionResult, IntegrationAdapter


class OktaAdapter(IntegrationAdapter):
    id = "okta"
    name = "Okta"

    def test_connection(self, config: dict[str, Any]) -> ConnectionResult:
        okta = config.get("identity", {}).get("okta", {})
        if not okta.get("enabled", False):
            return ConnectionResult(False, "Okta integration is disabled — enable it first")
        domain = okta.get("domain") or os.environ.get(okta.get("domain_env", "OKTA_DOMAIN"), "")
        token = os.environ.get(okta.get("token_env", "OKTA_API_TOKEN"), "")
        if not domain:
            return ConnectionResult(False, "Set Okta domain in Settings or OKTA_DOMAIN env var")
        if not token:
            return ConnectionResult(False, "Set OKTA_API_TOKEN environment variable")
        domain = domain.removeprefix("https://").rstrip("/")
        try:
            url = f"https://{domain}/api/v1/users?limit=1"
            req = urllib.request.Request(
                url,
                headers={"Authorization": f"SSWS {token}", "Accept": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310
                json.loads(resp.read().decode())
            return ConnectionResult(True, f"Connected to Okta org {domain}")
        except urllib.error.HTTPError as exc:
            return ConnectionResult(False, f"Okta API error {exc.code}: {exc.reason}")
        except Exception as exc:  # noqa: BLE001
            return ConnectionResult(False, f"Okta connection failed: {exc}")
