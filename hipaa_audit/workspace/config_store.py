from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from hipaa_audit.controls import PACKAGE_ROOT, load_config


def config_path(repo_path: Path) -> Path:
    p = repo_path / "hipaa-audit.yaml"
    return p if p.exists() else repo_path / "hipaa-audit.example.yaml"


def load_workspace_config(repo_path: Path) -> dict[str, Any]:
    path = config_path(repo_path)
    if path.exists():
        return load_config(path)
    return yaml.safe_load((PACKAGE_ROOT / "hipaa-audit.example.yaml").read_text()) or {}


def save_workspace_config(repo_path: Path, config: dict[str, Any]) -> Path:
    dest = repo_path / "hipaa-audit.yaml"
    dest.write_text(yaml.dump(config, sort_keys=False, default_flow_style=False))
    return dest


def ensure_bootstrapped(repo_path: Path) -> bool:
    """Return True if workspace looks initialized."""
    return (repo_path / "hipaa-audit.yaml").exists() and (repo_path / "policies").is_dir()


def integration_status(config: dict[str, Any]) -> list[dict[str, Any]]:
    cards = [
        {
            "id": "aws",
            "name": "Amazon Web Services",
            "enabled": config.get("aws", {}).get("enabled", False),
            "hint": "Uses AWS credentials from environment or ~/.aws",
        },
        {
            "id": "github",
            "name": "GitHub",
            "enabled": config.get("github", {}).get("enabled", False),
            "hint": "Set GITHUB_TOKEN and repo slug in settings",
        },
        {
            "id": "okta",
            "name": "Okta",
            "enabled": config.get("identity", {}).get("okta", {}).get("enabled", False),
            "hint": "Set OKTA_API_TOKEN and Okta domain",
        },
        {
            "id": "google",
            "name": "Google Workspace",
            "enabled": config.get("identity", {}).get("google", {}).get("enabled", False),
            "hint": "Service account + GOOGLE_APPLICATION_CREDENTIALS",
        },
        {
            "id": "prowler",
            "name": "Prowler",
            "enabled": config.get("integrations", {}).get("prowler", {}).get("enabled", False),
            "hint": "Run collect-external-evidence.sh or prowler manually",
        },
        {
            "id": "personnel",
            "name": "Personnel",
            "enabled": config.get("personnel", {}).get("enabled", False),
            "hint": "Policy acks + training CSV",
        },
        {
            "id": "vendors",
            "name": "Vendor risk",
            "enabled": config.get("vendors", {}).get("enabled", False),
            "hint": "Vendor register + questionnaires",
        },
        {
            "id": "access_reviews",
            "name": "Access reviews",
            "enabled": config.get("access_reviews", {}).get("enabled", False),
            "hint": "Quarterly IAM/SaaS campaigns",
        },
        {
            "id": "devices",
            "name": "MDM devices",
            "enabled": config.get("devices", {}).get("enabled", False),
            "hint": "Jamf/Intune CSV import",
        },
        {
            "id": "saas_inventory",
            "name": "SaaS inventory",
            "enabled": config.get("saas_inventory", {}).get("enabled", False),
            "hint": "Okta/Google app discovery",
        },
    ]
    return cards


def apply_integration_toggle(config: dict[str, Any], integration_id: str, enabled: bool) -> dict[str, Any]:
    if integration_id == "aws":
        config.setdefault("aws", {})["enabled"] = enabled
    elif integration_id == "github":
        config.setdefault("github", {})["enabled"] = enabled
    elif integration_id == "okta":
        config.setdefault("identity", {}).setdefault("okta", {})["enabled"] = enabled
    elif integration_id == "google":
        config.setdefault("identity", {}).setdefault("google", {})["enabled"] = enabled
    elif integration_id == "prowler":
        config.setdefault("integrations", {}).setdefault("prowler", {})["enabled"] = enabled
    elif integration_id == "personnel":
        config.setdefault("personnel", {})["enabled"] = enabled
    elif integration_id == "vendors":
        config.setdefault("vendors", {})["enabled"] = enabled
    elif integration_id == "access_reviews":
        config.setdefault("access_reviews", {})["enabled"] = enabled
    elif integration_id == "devices":
        config.setdefault("devices", {})["enabled"] = enabled
    elif integration_id == "saas_inventory":
        config.setdefault("saas_inventory", {})["enabled"] = enabled
    return config
