from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from hipaa_audit.controls import PACKAGE_ROOT
from hipaa_audit.platform.adapters.aws import AwsAdapter
from hipaa_audit.platform.adapters.base import ConnectionResult, IntegrationAdapter
from hipaa_audit.platform.adapters.github import GithubAdapter
from hipaa_audit.platform.adapters.gitlab import GitLabAdapter
from hipaa_audit.platform.adapters.gcp import GcpAdapter
from hipaa_audit.platform.adapters.google import GoogleAdapter
from hipaa_audit.platform.adapters.intune import IntuneAdapter
from hipaa_audit.platform.adapters.jamf import JamfAdapter
from hipaa_audit.platform.adapters.okta import OktaAdapter
from hipaa_audit.platform.adapters.rippling import RipplingAdapter
from hipaa_audit.platform.adapters.snyk import SnykAdapter

_ADAPTERS: dict[str, IntegrationAdapter] = {
    a.id: a
    for a in (
        AwsAdapter(),
        GithubAdapter(),
        GitLabAdapter(),
        GcpAdapter(),
        OktaAdapter(),
        GoogleAdapter(),
        JamfAdapter(),
        IntuneAdapter(),
        RipplingAdapter(),
        SnykAdapter(),
    )
}

_REGISTER_INTEGRATIONS = {
    "personnel": ("personnel", "register_path", "compliance/acknowledgments.yaml"),
    "vendors": ("vendors", "register_path", "compliance/vendors.yaml"),
    "access_reviews": ("access_reviews", "register_path", "compliance/access-reviews.yaml"),
    "devices": ("devices", "register_path", "compliance/devices.yaml"),
    "saas_inventory": ("saas_inventory", "register_path", "compliance/saas-inventory.yaml"),
}


def get_adapter(integration_id: str) -> IntegrationAdapter | None:
    return _ADAPTERS.get(integration_id)


def load_integrations_registry() -> dict[str, Any]:
    path = PACKAGE_ROOT / "platform" / "integrations_registry.yaml"
    return yaml.safe_load(path.read_text()) or {}


def test_integration_connection(
    integration_id: str,
    config: dict[str, Any],
    *,
    repo_path: Path | None = None,
) -> ConnectionResult:
    adapter = get_adapter(integration_id)
    if adapter:
        return adapter.test_connection(config)

    if integration_id == "prowler":
        if repo_path is None:
            return ConnectionResult(False, "Workspace path required for Prowler ingest check")
        glob = list((repo_path / "evidence" / "prowler").glob("*.json"))
        if glob:
            return ConnectionResult(True, f"Found {len(glob)} Prowler AWS evidence file(s)")
        return ConnectionResult(
            False,
            "No Prowler output in evidence/prowler/ — run collect-external-evidence.sh",
        )

    if integration_id == "prowler_azure":
        if repo_path is None:
            return ConnectionResult(False, "Workspace path required")
        glob = list((repo_path / "evidence" / "prowler-azure").glob("*.json"))
        if glob:
            return ConnectionResult(True, f"Found {len(glob)} Prowler Azure evidence file(s)")
        return ConnectionResult(False, "No Prowler output in evidence/prowler-azure/")

    if integration_id == "prowler_gcp":
        if repo_path is None:
            return ConnectionResult(False, "Workspace path required")
        glob = list((repo_path / "evidence" / "prowler-gcp").glob("*.json"))
        if glob:
            return ConnectionResult(True, f"Found {len(glob)} Prowler GCP evidence file(s)")
        return ConnectionResult(False, "No Prowler output in evidence/prowler-gcp/")

    if integration_id in _REGISTER_INTEGRATIONS:
        section, key, default = _REGISTER_INTEGRATIONS[integration_id]
        if not config.get(section, {}).get("enabled", False):
            return ConnectionResult(False, f"{integration_id.replace('_', ' ').title()} is disabled")
        rel = config.get(section, {}).get(key, default)
        path = (repo_path / rel) if repo_path else Path(rel)
        if path.exists():
            return ConnectionResult(True, f"Register found at {rel}")
        return ConnectionResult(False, f"Register missing — create {rel}")

    return ConnectionResult(False, f"No connection test for integration: {integration_id}")


def record_connection_test(
    config: dict[str, Any],
    integration_id: str,
    result: ConnectionResult,
) -> dict[str, Any]:
    config.setdefault("workspace", {}).setdefault("connection_tests", {})[integration_id] = {
        "ok": result.ok,
        "message": result.message,
        "tested_at": datetime.now(UTC).isoformat(),
    }
    return config
