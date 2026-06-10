from __future__ import annotations

import base64
import os
from typing import Any

from hipaa_audit.platform.adapters.base import ConnectionResult, IntegrationAdapter


class BambooHRAdapter(IntegrationAdapter):
    id = "bamboohr"
    name = "BambooHR"

    def _api_key(self) -> str:
        return os.environ.get("BAMBOOHR_API_KEY", "")

    def _company(self, config: dict[str, Any]) -> str:
        return (
            os.environ.get("BAMBOOHR_COMPANY", "")
            or config.get("personnel", {}).get("bamboohr", {}).get("company_domain", "")
        )

    def _auth_header(self) -> dict[str, str]:
        token = base64.b64encode(f"{self._api_key()}:x".encode()).decode()
        return {"Authorization": f"Basic {token}", "Accept": "application/json"}

    def _get(self, config: dict[str, Any], path: str) -> list[dict[str, Any]]:
        company = self._company(config)
        if not self._api_key() or not company:
            return []
        import httpx  # noqa: PLC0415

        url = f"https://api.bamboohr.com/api/gateway.php/{company}/v1{path}"
        resp = httpx.get(url, headers=self._auth_header(), timeout=30.0)
        if resp.status_code != 200:
            return []
        data = resp.json()
        if isinstance(data, list):
            return data
        return data.get("employees") or data.get("data") or []

    def test_connection(self, config: dict[str, Any]) -> ConnectionResult:
        if not self._api_key():
            return ConnectionResult(False, "Missing env: BAMBOOHR_API_KEY")
        company = self._company(config)
        if not company:
            return ConnectionResult(False, "Missing BambooHR company subdomain (BAMBOOHR_COMPANY)")
        rows = self._get(config, "/employees/directory")
        if rows:
            return ConnectionResult(True, f"BambooHR connected ({len(rows)} employee(s) in directory)")
        return ConnectionResult(False, "BambooHR API returned no employees — check API key and company subdomain")

    def discover(self, config: dict[str, Any]) -> list[dict[str, Any]]:
        workforce: list[dict[str, Any]] = []
        for row in self._get(config, "/employees/directory"):
            emp_id = row.get("id") or row.get("employeeId")
            email = row.get("workEmail") or row.get("work_email") or ""
            if not emp_id:
                continue
            workforce.append(
                {
                    "id": str(emp_id),
                    "email": email,
                    "active": True,
                    "hire_date": (row.get("hireDate") or row.get("hire_date") or "")[:10],
                    "source": "bamboohr",
                }
            )
        return workforce
