from __future__ import annotations

import json
import os
import urllib.request
from typing import Any


def list_okta_users(config: dict[str, Any], *, limit: int = 100) -> list[str]:
    okta = config.get("identity", {}).get("okta", {})
    if not okta.get("enabled", False):
        return []
    domain = okta.get("domain") or os.environ.get(okta.get("domain_env", "OKTA_DOMAIN"), "")
    token = os.environ.get(okta.get("token_env", "OKTA_API_TOKEN"), "")
    if not domain or not token:
        return []
    domain = domain.removeprefix("https://").rstrip("/")
    url = f"https://{domain}/api/v1/users?limit={limit}"
    req = urllib.request.Request(
        url,
        headers={"Authorization": f"SSWS {token}", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:  # noqa: S310
            users = json.loads(resp.read().decode())
    except Exception:  # noqa: BLE001
        return []
    principals: list[str] = []
    for u in users:
        login = (u.get("profile") or {}).get("login") or u.get("login", "")
        if login:
            principals.append(login)
    return principals
