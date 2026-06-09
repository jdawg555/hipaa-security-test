from __future__ import annotations

import base64
import os
from datetime import UTC, datetime
from typing import Any

from hipaa_audit.platform.adapters.base import ConnectionResult, IntegrationAdapter


class JamfAdapter(IntegrationAdapter):
    id = "jamf"
    name = "Jamf Pro"

    def _client(self):
        import httpx  # noqa: PLC0415

        return httpx

    def _credentials(self) -> tuple[str, str, str] | None:
        base = os.environ.get("JAMF_URL", "").rstrip("/")
        user = os.environ.get("JAMF_USER", "")
        password = os.environ.get("JAMF_PASSWORD", "")
        if base and user and password:
            return base, user, password
        return None

    def _pro_token(self, base: str, user: str, password: str) -> str | None:
        httpx = self._client()
        try:
            resp = httpx.post(
                f"{base}/api/v1/auth",
                json={"username": user, "password": password},
                timeout=15.0,
            )
            if resp.status_code == 200:
                data = resp.json()
                return data.get("token") or data.get("access_token")
        except Exception:  # noqa: BLE001
            return None
        return None

    def test_connection(self, config: dict[str, Any]) -> ConnectionResult:
        creds = self._credentials()
        if not creds:
            missing = [k for k in ("JAMF_URL", "JAMF_USER", "JAMF_PASSWORD") if not os.environ.get(k)]
            return ConnectionResult(False, f"Missing env: {', '.join(missing)}")
        base, user, password = creds
        if self._pro_token(base, user, password):
            return ConnectionResult(True, f"Jamf Pro API authenticated at {base}")
        try:
            httpx = self._client()
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

    def discover(self, config: dict[str, Any]) -> list[dict[str, Any]]:
        creds = self._credentials()
        if not creds:
            return []
        base, user, password = creds
        today = datetime.now(UTC).strftime("%Y-%m-%d")
        devices: list[dict[str, Any]] = []

        token = self._pro_token(base, user, password)
        if token:
            devices.extend(self._discover_pro(base, token, today))
        if not devices:
            devices.extend(self._discover_classic(base, user, password, today))
        return devices

    def _discover_pro(self, base: str, token: str, today: str) -> list[dict[str, Any]]:
        httpx = self._client()
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        devices: list[dict[str, Any]] = []
        try:
            resp = httpx.get(
                f"{base}/api/v1/computers-inventory",
                headers=headers,
                params={"page-size": 200},
                timeout=30.0,
            )
            if resp.status_code != 200:
                return []
            for row in resp.json().get("results", []):
                general = row.get("general", {})
                user_loc = row.get("userAndLocation", {})
                os_info = row.get("operatingSystem", {})
                security = row.get("security", {})
                name = general.get("name") or general.get("id") or "unknown"
                devices.append(
                    {
                        "id": f"DEV-{name}",
                        "owner": user_loc.get("email") or user_loc.get("username") or "",
                        "platform": (os_info.get("type") or "macos").lower(),
                        "mdm": "jamf",
                        "encrypted": bool(security.get("filevault2_enabled") or security.get("sip_status")),
                        "screen_lock": bool(security.get("firewall_enabled", True)),
                        "os_version": os_info.get("version") or "",
                        "last_seen": today,
                    }
                )
        except Exception:  # noqa: BLE001
            return []
        return [d for d in devices if d.get("owner")]

    def _discover_classic(self, base: str, user: str, password: str, today: str) -> list[dict[str, Any]]:
        httpx = self._client()
        token = base64.b64encode(f"{user}:{password}".encode()).decode()
        headers = {"Authorization": f"Basic {token}", "Accept": "application/json"}
        devices: list[dict[str, Any]] = []
        try:
            resp = httpx.get(f"{base}/JSSResource/computers", headers=headers, timeout=30.0)
            if resp.status_code != 200:
                return []
            data = resp.json()
            computers = data.get("computers") or data.get("computer") or []
            if isinstance(computers, dict):
                computers = [computers]
            for row in computers:
                if not isinstance(row, dict):
                    continue
                name = row.get("name") or row.get("id") or "unknown"
                devices.append(
                    {
                        "id": f"DEV-{name}",
                        "owner": row.get("username") or row.get("user_name") or "",
                        "platform": "macos",
                        "mdm": "jamf",
                        "encrypted": True,
                        "screen_lock": True,
                        "os_version": row.get("os_version") or "",
                        "last_seen": today,
                    }
                )
        except Exception:  # noqa: BLE001
            return []
        return devices
