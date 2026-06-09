from __future__ import annotations

import os
from typing import Any


def graph_token_from_env() -> str | None:
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


def azure_enabled(config: dict[str, Any]) -> bool:
    identity = config.get("identity", {}).get("azure", {})
    if identity.get("enabled", False):
        return True
    return config.get("devices", {}).get("enabled", False) and bool(graph_token_from_env())
