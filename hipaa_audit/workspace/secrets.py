from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

SECRET_ENV_MAP = {
    "github_token": "GITHUB_TOKEN",
    "okta_api_token": "OKTA_API_TOKEN",
    "gitlab_token": "GITLAB_TOKEN",
    "google_credentials_path": "GOOGLE_APPLICATION_CREDENTIALS",
    "slack_webhook_url": "SLACK_WEBHOOK_URL",
    "jamf_url": "JAMF_URL",
    "jamf_user": "JAMF_USER",
    "jamf_password": "JAMF_PASSWORD",
    "azure_tenant_id": "AZURE_TENANT_ID",
    "azure_client_id": "AZURE_CLIENT_ID",
    "azure_client_secret": "AZURE_CLIENT_SECRET",
    "github_oauth_client_id": "GITHUB_OAUTH_CLIENT_ID",
    "github_oauth_client_secret": "GITHUB_OAUTH_CLIENT_SECRET",
    "rippling_api_token": "RIPPLING_API_TOKEN",
    "bamboohr_api_key": "BAMBOOHR_API_KEY",
    "bamboohr_company": "BAMBOOHR_COMPANY",
    "gitlab_oauth_client_id": "GITLAB_OAUTH_CLIENT_ID",
    "gitlab_oauth_client_secret": "GITLAB_OAUTH_CLIENT_SECRET",
    "snyk_token": "SNYK_TOKEN",
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
        {"key": "github_oauth_client_id", "label": "OAuth client ID", "type": "text", "hint": "Or use Connect with GitHub below"},
        {"key": "github_oauth_client_secret", "label": "OAuth client secret", "type": "password"},
        {"key": "github_token", "label": "Personal access token (manual)", "type": "password", "hint": "repo + read:org scope"},
    ],
    "rippling": [
        {"key": "rippling_api_token", "label": "Rippling API token", "type": "password", "hint": "Platform API bearer token"},
    ],
    "bamboohr": [
        {"key": "bamboohr_company", "label": "Company subdomain", "type": "text", "hint": "yourcompany from yourcompany.bamboohr.com"},
        {"key": "bamboohr_api_key", "label": "BambooHR API key", "type": "password", "hint": "Settings → API Keys in BambooHR"},
    ],
    "snyk": [
        {"key": "snyk_token", "label": "Snyk API token", "type": "password", "hint": "service account or personal token"},
    ],
    "okta": [
        {"key": "okta_api_token", "label": "Okta API token", "type": "password", "hint": "SSWS admin token"},
    ],
    "gitlab": [
        {"key": "gitlab_oauth_client_id", "label": "OAuth application ID", "type": "text", "hint": "Or use Connect with GitLab below"},
        {"key": "gitlab_oauth_client_secret", "label": "OAuth application secret", "type": "password"},
        {"key": "gitlab_token", "label": "Personal access token (manual)", "type": "password", "hint": "api scope"},
    ],
    "gcp": [
        {
            "key": "google_credentials_path",
            "label": "Service account JSON path",
            "type": "text",
            "hint": "Sets GOOGLE_APPLICATION_CREDENTIALS for GCP / Prowler",
        },
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
    "intune": [
        {"key": "azure_tenant_id", "label": "Azure tenant ID", "type": "text"},
        {"key": "azure_client_id", "label": "Azure app client ID", "type": "text"},
        {"key": "azure_client_secret", "label": "Azure client secret", "type": "password"},
    ],
    "aws": [
        {"key": "aws_note", "label": "AWS credentials", "type": "info", "hint": "Use env vars or IAM role — set region in Settings"},
    ],
    "prowler": [
        {"key": "prowler_note", "label": "Prowler ingest", "type": "info", "hint": "Run scripts/collect-external-evidence.sh — no API key needed"},
    ],
}
