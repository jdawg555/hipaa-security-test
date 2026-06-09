from __future__ import annotations

import os
from typing import Any

from hipaa_audit.platform.adapters.base import ConnectionResult, IntegrationAdapter


class RipplingAdapter(IntegrationAdapter):
    id = "rippling"
    name = "Rippling HRIS"

    def _token(self) -> str | None:
        return os.environ.get("RIPPLING_API_TOKEN", "")

    def _get(self, path: str) -> list[dict[str, Any]]:
        token = self._token()
        if not token:
            return []
        import httpx  # noqa: PLC0415

        resp = httpx.get(
            f"https://api.rippling.com/platform/api{path}",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
            timeout=30.0,
        )
        if resp.status_code != 200:
            return []
        data = resp.json()
        if isinstance(data, list):
            return data
        return data.get("items") or data.get("employees") or []

    def test_connection(self, config: dict[str, Any]) -> ConnectionResult:
        if not os.environ.get("RIPPLING_API_TOKEN"):
            return ConnectionResult(False, "Missing env: RIPPLING_API_TOKEN")
        rows = self._get("/employees")
        if rows:
            return ConnectionResult(True, f"Rippling API connected ({len(rows)} employee record(s))")
        return ConnectionResult(False, "Rippling API returned no employees — check token scope")

    def discover(self, config: dict[str, Any]) -> list[dict[str, Any]]:
        workforce: list[dict[str, Any]] = []
        for row in self._get("/employees"):
            emp_id = row.get("id") or row.get("employee_id") or row.get("work_email", "")
            email = row.get("work_email") or row.get("email") or ""
            if not emp_id:
                continue
            workforce.append(
                {
                    "id": str(emp_id),
                    "email": email,
                    "active": row.get("status", "active") in ("active", "ACTIVE", True),
                    "hire_date": (row.get("start_date") or row.get("hire_date") or "")[:10],
                    "source": "rippling",
                }
            )
        return workforce
