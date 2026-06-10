from __future__ import annotations

import json
import os
import secrets
import urllib.parse
import urllib.request
from typing import Any


OAUTH_PROVIDERS: dict[str, dict[str, Any]] = {
    "github": {
        "name": "GitHub",
        "authorize_url": "https://github.com/login/oauth/authorize",
        "token_url": "https://github.com/login/oauth/access_token",
        "scopes": ["read:org", "repo"],
        "client_id_env": "GITHUB_OAUTH_CLIENT_ID",
        "client_secret_env": "GITHUB_OAUTH_CLIENT_SECRET",
        "client_id_secret": "github_oauth_client_id",
        "client_secret_secret": "github_oauth_client_secret",
        "token_secret": "github_token",
    },
    "gitlab": {
        "name": "GitLab",
        "authorize_url": "https://gitlab.com/oauth/authorize",
        "token_url": "https://gitlab.com/oauth/token",
        "scopes": ["read_api", "read_repository"],
        "token_grant_type": "authorization_code",
        "client_id_env": "GITLAB_OAUTH_CLIENT_ID",
        "client_secret_env": "GITLAB_OAUTH_CLIENT_SECRET",
        "client_id_secret": "gitlab_oauth_client_id",
        "client_secret_secret": "gitlab_oauth_client_secret",
        "token_secret": "gitlab_token",
    },
}


def oauth_credentials(
    provider: str,
    *,
    config: dict[str, Any] | None = None,
    secrets: dict[str, str] | None = None,
) -> tuple[str, str] | None:
    meta = OAUTH_PROVIDERS.get(provider)
    if not meta:
        return None
    secrets = secrets or {}
    client_id = (
        secrets.get(meta["client_id_secret"])
        or os.environ.get(meta["client_id_env"], "")
        or (config or {}).get("oauth", {}).get(provider, {}).get("client_id", "")
    )
    client_secret = secrets.get(meta["client_secret_secret"]) or os.environ.get(
        meta["client_secret_env"], ""
    )
    if client_id and client_secret:
        return client_id, client_secret
    return None


def oauth_available(provider: str, *, config: dict[str, Any] | None = None, secrets: dict[str, str] | None = None) -> bool:
    return oauth_credentials(provider, config=config, secrets=secrets) is not None


def new_oauth_state() -> str:
    return secrets.token_urlsafe(24)


def authorize_url(
    provider: str,
    *,
    redirect_uri: str,
    state: str,
    config: dict[str, Any] | None = None,
    secrets: dict[str, str] | None = None,
) -> str | None:
    meta = OAUTH_PROVIDERS.get(provider)
    creds = oauth_credentials(provider, config=config, secrets=secrets)
    if not meta or not creds:
        return None
    client_id, _ = creds
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": " ".join(meta["scopes"]),
        "state": state,
        "response_type": "code",
    }
    return f"{meta['authorize_url']}?{urllib.parse.urlencode(params)}"


def exchange_code(
    provider: str,
    *,
    code: str,
    redirect_uri: str,
    config: dict[str, Any] | None = None,
    secrets: dict[str, str] | None = None,
) -> tuple[str | None, str | None]:
    """Returns (access_token, error_message)."""
    meta = OAUTH_PROVIDERS.get(provider)
    creds = oauth_credentials(provider, config=config, secrets=secrets)
    if not meta or not creds:
        return None, "OAuth credentials not configured"
    client_id, client_secret = creds
    payload = {
        "client_id": client_id,
        "client_secret": client_secret,
        "code": code,
        "redirect_uri": redirect_uri,
    }
    if meta.get("token_grant_type"):
        payload["grant_type"] = meta["token_grant_type"]
    payload_bytes = urllib.parse.urlencode(payload).encode()
    req = urllib.request.Request(
        meta["token_url"],
        data=payload_bytes,
        headers={"Accept": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:  # noqa: S310
            data = json.loads(resp.read().decode())
    except Exception as exc:  # noqa: BLE001
        return None, f"Token exchange failed: {exc}"
    token = data.get("access_token")
    if not token:
        return None, data.get("error_description") or data.get("error") or "No access token in response"
    return token, None


def oauth_redirect_base(config: dict[str, Any]) -> str:
    return config.get("workspace", {}).get("oauth_redirect_base", "http://127.0.0.1:8787").rstrip("/")
