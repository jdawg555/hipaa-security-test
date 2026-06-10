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


def _connection_badge(config: dict[str, Any], integration_id: str) -> dict[str, Any] | None:
    test = config.get("workspace", {}).get("connection_tests", {}).get(integration_id)
    if not test:
        return None
    return {
        "ok": test.get("ok", False),
        "message": test.get("message", ""),
        "tested_at": test.get("tested_at", ""),
    }


def integration_status(config: dict[str, Any]) -> list[dict[str, Any]]:
    cards = [
        {
            "id": "aws",
            "name": "Amazon Web Services",
            "enabled": config.get("aws", {}).get("enabled", False),
            "hint": "Uses AWS credentials from environment or ~/.aws",
            "testable": True,
        },
        {
            "id": "github",
            "name": "GitHub",
            "enabled": config.get("github", {}).get("enabled", False),
            "hint": "Set GITHUB_TOKEN and repo slug in settings",
            "testable": True,
        },
        {
            "id": "gitlab",
            "name": "GitLab",
            "enabled": config.get("gitlab", {}).get("enabled", False),
            "hint": "Set GITLAB_TOKEN and gitlab.project in Settings",
            "testable": True,
        },
        {
            "id": "gcp",
            "name": "Google Cloud",
            "enabled": config.get("gcp", {}).get("enabled", False),
            "hint": "GOOGLE_APPLICATION_CREDENTIALS + Prowler GCP evidence",
            "testable": True,
        },
        {
            "id": "prowler_azure",
            "name": "Prowler Azure",
            "enabled": config.get("integrations", {}).get("prowler_azure", {}).get("enabled", False),
            "hint": "Run prowler azure --compliance hipaa_azure",
            "testable": True,
        },
        {
            "id": "prowler_gcp",
            "name": "Prowler GCP",
            "enabled": config.get("integrations", {}).get("prowler_gcp", {}).get("enabled", False),
            "hint": "Run prowler gcp --compliance hipaa_gcp",
            "testable": True,
        },
        {
            "id": "okta",
            "name": "Okta",
            "enabled": config.get("identity", {}).get("okta", {}).get("enabled", False),
            "hint": "Set OKTA_API_TOKEN and Okta domain",
            "testable": True,
        },
        {
            "id": "google",
            "name": "Google Workspace",
            "enabled": config.get("identity", {}).get("google", {}).get("enabled", False),
            "hint": "Service account + GOOGLE_APPLICATION_CREDENTIALS",
            "testable": True,
        },
        {
            "id": "prowler",
            "name": "Prowler",
            "enabled": config.get("integrations", {}).get("prowler", {}).get("enabled", False),
            "hint": "Run collect-external-evidence.sh or prowler manually",
            "testable": True,
        },
        {
            "id": "snyk",
            "name": "Snyk",
            "enabled": config.get("integrations", {}).get("snyk", {}).get("enabled", False),
            "hint": "Set SNYK_TOKEN — ingest JSON to evidence/snyk/",
            "testable": True,
        },
        {
            "id": "personnel",
            "name": "Personnel",
            "enabled": config.get("personnel", {}).get("enabled", False),
            "hint": "Policy acks + training CSV",
            "testable": True,
        },
        {
            "id": "vendors",
            "name": "Vendor risk",
            "enabled": config.get("vendors", {}).get("enabled", False),
            "hint": "Vendor register + questionnaires",
            "testable": True,
        },
        {
            "id": "access_reviews",
            "name": "Access reviews",
            "enabled": config.get("access_reviews", {}).get("enabled", False),
            "hint": "Quarterly IAM/SaaS campaigns",
            "testable": True,
        },
        {
            "id": "devices",
            "name": "MDM devices",
            "enabled": config.get("devices", {}).get("enabled", False),
            "hint": "Jamf/Intune CSV import or Jamf API",
            "testable": True,
        },
        {
            "id": "jamf",
            "name": "Jamf Pro",
            "enabled": config.get("devices", {}).get("enabled", False),
            "hint": "Set JAMF_URL, JAMF_USER, JAMF_PASSWORD",
            "testable": True,
        },
        {
            "id": "intune",
            "name": "Microsoft Intune",
            "enabled": config.get("devices", {}).get("enabled", False),
            "hint": "Set AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET",
            "testable": True,
        },
        {
            "id": "rippling",
            "name": "Rippling HRIS",
            "enabled": config.get("personnel", {}).get("enabled", False),
            "hint": "Set RIPPLING_API_TOKEN for workforce sync",
            "testable": True,
        },
        {
            "id": "bamboohr",
            "name": "BambooHR",
            "enabled": config.get("personnel", {}).get("enabled", False),
            "hint": "Set BAMBOOHR_API_KEY + BAMBOOHR_COMPANY for workforce sync",
            "testable": True,
        },
        {
            "id": "saas_inventory",
            "name": "SaaS inventory",
            "enabled": config.get("saas_inventory", {}).get("enabled", False),
            "hint": "Okta/Google app discovery",
            "testable": True,
        },
    ]
    for card in cards:
        card["connection"] = _connection_badge(config, card["id"])
    return cards


def apply_integration_toggle(config: dict[str, Any], integration_id: str, enabled: bool) -> dict[str, Any]:
    if integration_id == "aws":
        config.setdefault("aws", {})["enabled"] = enabled
    elif integration_id == "github":
        config.setdefault("github", {})["enabled"] = enabled
    elif integration_id == "gitlab":
        config.setdefault("gitlab", {})["enabled"] = enabled
    elif integration_id == "gcp":
        config.setdefault("gcp", {})["enabled"] = enabled
    elif integration_id == "okta":
        config.setdefault("identity", {}).setdefault("okta", {})["enabled"] = enabled
    elif integration_id == "google":
        config.setdefault("identity", {}).setdefault("google", {})["enabled"] = enabled
    elif integration_id == "prowler":
        config.setdefault("integrations", {}).setdefault("prowler", {})["enabled"] = enabled
    elif integration_id == "prowler_azure":
        config.setdefault("integrations", {}).setdefault("prowler_azure", {})["enabled"] = enabled
    elif integration_id == "prowler_gcp":
        config.setdefault("integrations", {}).setdefault("prowler_gcp", {})["enabled"] = enabled
    elif integration_id == "snyk":
        config.setdefault("integrations", {}).setdefault("snyk", {})["enabled"] = enabled
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
