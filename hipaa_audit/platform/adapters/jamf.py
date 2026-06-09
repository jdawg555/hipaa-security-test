from __future__ import annotations

import base64
import os
from typing import Any

from hipaa_audit.platform.adapters.base import ConnectionResult, IntegrationAdapter


class JamfAdapter(IntegrationAdapter):
    id = "jamf"
    name = "Jamf Pro"

    def test_connection(self, config: dict[str, Any]) -> ConnectionResult:
        missing = [k for k in ("JAMF_URL", "JAMF_USER", "JAMF_PASSWORD") if not os.environ.get(k)]
        if missing:
            return ConnectionResult(False, f"Missing env: {', '.join(missing)}")

        base = os.environ["JAMF_URL"].rstrip("/")
        user = os.environ["JAMF_USER"]
        password = os.environ["JAMF_PASSWORD"]

        try:
            import httpx  # noqa: PLC0415
        except ImportError:
            return ConnectionResult(False, "Install serve extras: pip install hipaa-audit[serve]")

        try:
            resp = httpx.post(
                f"{base}/api/v1/auth",
                json={"username": user, "password": password},
                timeout=15.0,
            )
            if resp.status_code == 200:
                return ConnectionResult(True, f"Jamf Pro API authenticated at {base}")
        except Exception:  # noqa: BLE001
            pass

        try:
            token = base64.b64encode(f"{user}:{password}".encode()).decode()
            resp = httpx.get(
                f"{base}/JSSResource/accounts",
                headers={"Authorization": f"Basic {token}", "Accept": "application/json"},
                timeout=15.0,
            )
            if resp.status_code == 200:
                return ConnectionResult(True, f"Jamf Classic API reachable at {base}")
            return ConnectionResult(False, f"Jamf API returned HTTP {resp.status_code}")
        except Exception as exc:  # noqa: BLE001
            return ConnectionResult(False, f"Jamf connection failed: {exc}")
