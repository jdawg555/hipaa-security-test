from __future__ import annotations

import os
from typing import Any

from hipaa_audit.platform.adapters.base import ConnectionResult, IntegrationAdapter


class GcpAdapter(IntegrationAdapter):
    id = "gcp"
    name = "Google Cloud Platform"

    def test_connection(self, config: dict[str, Any]) -> ConnectionResult:
        gcp = config.get("gcp", {})
        if not gcp.get("enabled", False):
            return ConnectionResult(False, "GCP integration is disabled")
        creds = os.environ.get(
            gcp.get("credentials_env", "GOOGLE_APPLICATION_CREDENTIALS"),
            gcp.get("credentials_file", ""),
        )
        if not creds:
            return ConnectionResult(
                False,
                "Set GOOGLE_APPLICATION_CREDENTIALS or run collect-external-evidence.sh for Prowler GCP",
            )
        try:
            from google.oauth2 import service_account  # noqa: PLC0415
            from googleapiclient.discovery import build  # noqa: PLC0415

            credentials = service_account.Credentials.from_service_account_file(
                creds,
                scopes=["https://www.googleapis.com/auth/cloud-platform.read-only"],
            )
            service = build("cloudresourcemanager", "v1", credentials=credentials, cache_discovery=False)
            service.projects().get(projectId=gcp.get("project_id") or credentials.project_id).execute()
            return ConnectionResult(True, "GCP Cloud Resource Manager API connected")
        except ImportError:
            return ConnectionResult(False, "Install identity extras: pip install hipaa-audit[identity]")
        except Exception as exc:  # noqa: BLE001
            return ConnectionResult(False, f"GCP connection failed: {exc}")
