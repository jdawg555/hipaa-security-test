from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from hipaa_audit.platform.adapters.base import ConnectionResult, IntegrationAdapter


class GoogleAdapter(IntegrationAdapter):
    id = "google"
    name = "Google Workspace"

    def test_connection(self, config: dict[str, Any]) -> ConnectionResult:
        google = config.get("identity", {}).get("google", {})
        if not google.get("enabled", False):
            return ConnectionResult(False, "Google Workspace integration is disabled — enable it first")
        creds_path = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS", "")
        if not creds_path or not Path(creds_path).is_file():
            return ConnectionResult(
                False,
                "Set GOOGLE_APPLICATION_CREDENTIALS to a service account JSON file",
            )
        admin = google.get("admin_email", "")
        try:
            from google.oauth2 import service_account  # noqa: PLC0415
            from googleapiclient.discovery import build  # noqa: PLC0415

            scopes = ["https://www.googleapis.com/auth/admin.directory.user.readonly"]
            creds = service_account.Credentials.from_service_account_file(creds_path, scopes=scopes)
            if admin:
                creds = creds.with_subject(admin)
            service = build("admin", "directory_v1", credentials=creds, cache_discovery=False)
            service.users().list(customer="my_customer", maxResults=1).execute()
            label = admin or "service account"
            return ConnectionResult(True, f"Connected to Google Workspace as {label}")
        except ImportError:
            return ConnectionResult(False, "Install identity extras: pip install hipaa-audit[identity]")
        except Exception as exc:  # noqa: BLE001
            return ConnectionResult(False, f"Google Workspace connection failed: {exc}")
