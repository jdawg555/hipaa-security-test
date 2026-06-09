from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

SECRET_ENV_MAP = {
    "github_token": "GITHUB_TOKEN",
    "okta_api_token": "OKTA_API_TOKEN",
    "google_credentials_path": "GOOGLE_APPLICATION_CREDENTIALS",
    "slack_webhook_url": "SLACK_WEBHOOK_URL",
    "jamf_url": "JAMF_URL",
    "jamf_user": "JAMF_USER",
    "jamf_password": "JAMF_PASSWORD",
}


def secrets_path(repo_path: Path, config: dict[str, Any]) -> Path:
    rel = config.get("workspace", {}).get("secrets_path", "compliance/.workspace-secrets.yaml")
    return repo_path / rel


def load_secrets(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    raw = yaml.safe_load(path.read_text()) or {}
    return {k: str(v) for k, v in raw.items() if v}


def save_secrets(path: Path, data: dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.dump(data, sort_keys=False, default_flow_style=False))


def merge_secrets(path: Path, updates: dict[str, str]) -> dict[str, str]:
    current = load_secrets(path)
    for key, value in updates.items():
        if value:
            current[key] = value
    save_secrets(path, current)
    return current


def apply_workspace_secrets(repo_path: Path, config: dict[str, Any]) -> None:
    """Load gitignored secrets into env vars when not already set."""
    for secret_key, env_var in SECRET_ENV_MAP.items():
        if os.environ.get(env_var):
            continue
        value = load_secrets(secrets_path(repo_path, config)).get(secret_key, "")
        if value:
            os.environ[env_var] = value


CONNECT_FIELDS: dict[str, list[dict[str, str]]] = {
    "github": [
        {"key": "github_token", "label": "GitHub token", "type": "password", "hint": "repo + read:org scope"},
    ],
    "okta": [
        {"key": "okta_api_token", "label": "Okta API token", "type": "password", "hint": "SSWS admin token"},
    ],
    "google": [
        {
            "key": "google_credentials_path",
            "label": "Service account JSON path",
            "type": "text",
            "hint": "Absolute path — also set admin email in Settings",
        },
    ],
    "jamf": [
        {"key": "jamf_url", "label": "Jamf URL", "type": "text", "hint": "https://yourorg.jamfcloud.com"},
        {"key": "jamf_user", "label": "Jamf API user", "type": "text"},
        {"key": "jamf_password", "label": "Jamf API password", "type": "password"},
    ],
    "aws": [
        {"key": "aws_note", "label": "AWS credentials", "type": "info", "hint": "Use env vars or IAM role — set region in Settings"},
    ],
    "prowler": [
        {"key": "prowler_note", "label": "Prowler ingest", "type": "info", "hint": "Run scripts/collect-external-evidence.sh — no API key needed"},
    ],
}
