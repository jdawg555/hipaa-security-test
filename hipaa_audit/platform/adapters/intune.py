from __future__ import annotations

import os
from datetime import UTC, datetime
from typing import Any

from hipaa_audit.platform.adapters.base import ConnectionResult, IntegrationAdapter


class IntuneAdapter(IntegrationAdapter):
    id = "intune"
    name = "Microsoft Intune"

    def _token(self) -> str | None:
        tenant = os.environ.get("AZURE_TENANT_ID", "")
        client_id = os.environ.get("AZURE_CLIENT_ID", "")
        secret = os.environ.get("AZURE_CLIENT_SECRET", "")
        if not all((tenant, client_id, secret)):
            return None
        import httpx  # noqa: PLC0415

        resp = httpx.post(
            f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
            data={
                "client_id": client_id,
                "client_secret": secret,
                "scope": "https://graph.microsoft.com/.default",
                "grant_type": "client_credentials",
            },
            timeout=20.0,
        )
        if resp.status_code != 200:
            return None
        return resp.json().get("access_token")

    def test_connection(self, config: dict[str, Any]) -> ConnectionResult:
        missing = [k for k in ("AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET") if not os.environ.get(k)]
        if missing:
            return ConnectionResult(False, f"Missing env: {', '.join(missing)}")
        token = self._token()
        if not token:
            return ConnectionResult(False, "Failed to obtain Microsoft Graph token")
        import httpx  # noqa: PLC0415

        resp = httpx.get(
            "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$top=1",
            headers={"Authorization": f"Bearer {token}"},
            timeout=20.0,
        )
        if resp.status_code == 200:
            return ConnectionResult(True, "Microsoft Intune Graph API connected")
        return ConnectionResult(False, f"Graph API returned HTTP {resp.status_code}")

    def discover(self, config: dict[str, Any]) -> list[dict[str, Any]]:
        token = self._token()
        if not token:
            return []
        import httpx  # noqa: PLC0415

        today = datetime.now(UTC).strftime("%Y-%m-%d")
        devices: list[dict[str, Any]] = []
        url = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$top=200"
        try:
            resp = httpx.get(url, headers={"Authorization": f"Bearer {token}"}, timeout=30.0)
            if resp.status_code != 200:
                return []
            for row in resp.json().get("value", []):
                owner = row.get("userPrincipalName") or row.get("emailAddress") or ""
                name = row.get("deviceName") or row.get("id", "device")
                devices.append(
                    {
                        "id": f"DEV-{name}",
                        "owner": owner,
                        "platform": (row.get("operatingSystem") or "unknown").lower(),
                        "mdm": "intune",
                        "encrypted": bool(row.get("isEncrypted")),
                        "screen_lock": True,
                        "os_version": row.get("osVersion") or "",
                        "last_seen": (row.get("lastSyncDateTime") or today)[:10],
                    }
                )
        except Exception:  # noqa: BLE001
            return []
        return [d for d in devices if d.get("owner")]
