from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml


def load_inventory(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"apps": [], "discovered_at": None, "source": None}
    return yaml.safe_load(path.read_text()) or {"apps": []}


def save_inventory(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.dump(data, sort_keys=False, default_flow_style=False))


def discover_okta_apps(domain: str, token: str) -> list[dict[str, Any]]:
    import urllib.request

    url = f"https://{domain.rstrip('/')}/api/v1/apps"
    req = urllib.request.Request(
        url,
        headers={"Authorization": f"SSWS {token}", "Accept": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
        raw = json.loads(resp.read().decode())
    apps = []
    for app in raw:
        label = app.get("label") or app.get("name") or app.get("id", "")
        apps.append(
            {
                "id": f"okta-{app.get('id', label)}",
                "name": label,
                "provider": "okta",
                "okta_app_id": app.get("id"),
                "status": app.get("status", "unknown").lower(),
                "sso": app.get("signOnMode") not in ("OPENID_CONNECT", "BASIC_AUTH"),
                "vendor_id": None,
                "phi_risk": "unknown",
            }
        )
    return apps


def merge_discovered(path: Path, discovered: list[dict[str, Any]], *, source: str) -> dict[str, Any]:
    data = load_inventory(path)
    existing = {a.get("id"): a for a in data.get("apps", [])}
    for app in discovered:
        prior = existing.get(app["id"], {})
        merged = {**prior, **app}
        if prior.get("vendor_id"):
            merged["vendor_id"] = prior["vendor_id"]
        if prior.get("phi_risk") and prior.get("phi_risk") != "unknown":
            merged["phi_risk"] = prior["phi_risk"]
        existing[app["id"]] = merged
    data["apps"] = list(existing.values())
    data["discovered_at"] = datetime.now(UTC).strftime("%Y-%m-%d")
    data["source"] = source
    save_inventory(path, data)
    return data


def link_app(path: Path, app_id: str, vendor_id: str, *, phi_risk: str = "") -> bool:
    data = load_inventory(path)
    for app in data.get("apps", []):
        if app.get("id") == app_id:
            app["vendor_id"] = vendor_id
            if phi_risk:
                app["phi_risk"] = phi_risk
            save_inventory(path, data)
            return True
    return False


def assess_inventory(
    inventory_path: Path,
    vendors_path: Path,
    config: dict[str, Any],
) -> tuple[str, str, list[str]]:
    data = load_inventory(inventory_path)
    apps = [a for a in data.get("apps", []) if a.get("status", "active") == "active"]
    if not apps:
        return "manual", "No SaaS inventory — run hipaa-audit apps discover", []

    vendor_names = {v.get("id"): v.get("name") for v in load_vendors_safe(vendors_path)}
    issues: list[str] = []
    unlinked = [a for a in apps if not a.get("vendor_id")]
    if unlinked:
        issues.append(f"{len(unlinked)} app(s) not linked to vendor register")

    for app in apps:
        vid = app.get("vendor_id")
        if vid and vid not in vendor_names:
            issues.append(f"{app.get('name')}: vendor {vid} missing from register")

    max_age = int(config.get("saas_inventory", {}).get("max_discovery_age_days", 90))
    discovered = data.get("discovered_at")
    if discovered:
        try:
            age = (datetime.now(UTC).date() - datetime.strptime(discovered, "%Y-%m-%d").date()).days
            if age > max_age:
                issues.append(f"Inventory stale ({age}d) — re-run apps discover")
        except ValueError:
            pass

    if not issues:
        return "pass", f"{len(apps)} SaaS app(s) inventoried and linked", []
    if len(issues) <= 2:
        return "warn", "; ".join(issues), issues
    return "fail", "; ".join(issues[:3]), issues


def load_vendors_safe(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    raw = yaml.safe_load(path.read_text()) or {}
    return raw.get("vendors", [])


def discover_google_apps(creds_path: str, admin_email: str) -> list[dict[str, Any]]:
    from google.oauth2 import service_account  # noqa: PLC0415
    from googleapiclient.discovery import build  # noqa: PLC0415

    scopes = ["https://www.googleapis.com/auth/admin.reports.audit.readonly"]
    credentials = service_account.Credentials.from_service_account_file(creds_path, scopes=scopes)
    delegated = credentials.with_subject(admin_email)
    service = build("admin", "reports_v1", credentials=delegated, cache_discovery=False)
    activities = (
        service.activities()
        .list(userKey="all", applicationName="token", maxResults=500)
        .execute()
    )
    seen: dict[str, dict[str, Any]] = {}
    for item in activities.get("items", []):
        for event in item.get("events", []):
            params = {p.get("name"): p.get("value") for p in event.get("parameters", [])}
            name = params.get("client_name") or params.get("app_name") or params.get("application_name")
            if not name:
                continue
            app_id = f"google-{name.lower().replace(' ', '-')[:40]}"
            seen[app_id] = {
                "id": app_id,
                "name": name,
                "provider": "google",
                "status": "active",
                "sso": True,
                "vendor_id": None,
                "phi_risk": "unknown",
                "scopes": params.get("scope"),
            }
    return list(seen.values())


def import_google_apps_csv(csv_path: Path) -> list[dict[str, Any]]:
    import csv

    apps: list[dict[str, Any]] = []
    with csv_path.open(newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            name = (row.get("app_name") or row.get("name") or row.get("Application") or "").strip()
            if not name:
                continue
            app_id = f"google-{name.lower().replace(' ', '-')[:40]}"
            apps.append(
                {
                    "id": app_id,
                    "name": name,
                    "provider": "google",
                    "status": (row.get("status") or "active").lower(),
                    "sso": True,
                    "vendor_id": None,
                    "phi_risk": "unknown",
                    "users": row.get("users") or row.get("user_count"),
                }
            )
    return apps


def google_config_from_identity(config: dict[str, Any]) -> tuple[str, str] | None:
    google = config.get("identity", {}).get("google", {})
    if not google.get("enabled", False):
        return None
    creds_path = google.get("credentials_file") or os.environ.get(
        google.get("credentials_env", "GOOGLE_APPLICATION_CREDENTIALS"), ""
    )
    admin = google.get("admin_email") or os.environ.get(google.get("admin_email_env", "GOOGLE_ADMIN_EMAIL"), "")
    if creds_path and admin:
        return creds_path, admin
    return None


def okta_config_from_identity(config: dict[str, Any]) -> tuple[str, str] | None:
    okta = config.get("identity", {}).get("okta", {})
    if not okta.get("enabled", False):
        return None
    domain = okta.get("domain") or os.environ.get(okta.get("domain_env", "OKTA_DOMAIN"), "")
    token = os.environ.get(okta.get("token_env", "OKTA_API_TOKEN"), "")
    if domain and token:
        return domain.rstrip("/"), token
    return None
