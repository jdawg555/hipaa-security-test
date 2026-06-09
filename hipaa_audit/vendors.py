from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

SIG_LITE_KEYS = [
    "soc2_or_iso",
    "encryption_at_rest",
    "encryption_in_transit",
    "mfa_enforced",
    "access_logging",
    "incident_notification",
    "subprocessors_disclosed",
    "data_retention_defined",
]


def load_vendors(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"vendors": []}
    return yaml.safe_load(path.read_text()) or {"vendors": []}


def save_vendors(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.dump(data, sort_keys=False, default_flow_style=False))


def add_vendor(
    path: Path,
    *,
    name: str,
    phi_access: str = "none",
    risk_tier: str = "medium",
    baa_executed: bool = False,
) -> dict[str, Any]:
    data = load_vendors(path)
    seq = len(data.get("vendors", [])) + 1
    vendor = {
        "id": f"VND-{seq:03d}",
        "name": name,
        "phi_access": phi_access,
        "risk_tier": risk_tier,
        "baa_executed": baa_executed,
        "baa_date": None,
        "last_review": None,
        "review_interval_days": 365 if risk_tier == "high" else 730,
        "questionnaire": {k: None for k in SIG_LITE_KEYS},
    }
    data.setdefault("vendors", []).append(vendor)
    save_vendors(path, data)
    return vendor


def update_vendor(path: Path, vendor_id: str, **fields: Any) -> bool:
    data = load_vendors(path)
    allowed = {
        "name",
        "phi_access",
        "risk_tier",
        "baa_executed",
        "baa_date",
        "last_review",
        "review_interval_days",
    }
    for vendor in data.get("vendors", []):
        if vendor.get("id") != vendor_id:
            continue
        for key, value in fields.items():
            if key in allowed and value is not None:
                if key == "baa_executed":
                    vendor[key] = str(value).lower() in ("true", "1", "yes", "on")
                else:
                    vendor[key] = value
        save_vendors(path, data)
        return True
    return False


def delete_vendor(path: Path, vendor_id: str) -> bool:
    data = load_vendors(path)
    before = len(data.get("vendors", []))
    data["vendors"] = [v for v in data.get("vendors", []) if v.get("id") != vendor_id]
    if len(data["vendors"]) == before:
        return False
    save_vendors(path, data)
    return True


def review_vendor(
    path: Path,
    vendor_id: str,
    questionnaire: dict[str, Any],
    *,
    reviewer: str = "",
) -> bool:
    data = load_vendors(path)
    for vendor in data.get("vendors", []):
        if vendor.get("id") != vendor_id:
            continue
        vendor["questionnaire"].update(questionnaire)
        vendor["last_review"] = datetime.now(UTC).strftime("%Y-%m-%d")
        vendor["reviewed_by"] = reviewer
        save_vendors(path, data)
        return True
    return False


def assess_vendors(path: Path, config: dict[str, Any]) -> tuple[str, str, list[str]]:
    data = load_vendors(path)
    vendors = data.get("vendors", [])
    if not vendors:
        return "manual", "No vendor register — copy compliance/vendors.example.yaml", []

    issues: list[str] = []
    now = datetime.now(UTC).date()

    for v in vendors:
        name = v.get("name", v.get("id", "?"))
        phi = (v.get("phi_access") or "none").lower()
        if phi in ("full", "partial") and not v.get("baa_executed"):
            issues.append(f"{name}: PHI access without BAA")

        interval = int(v.get("review_interval_days", 365))
        last = _parse_date(v.get("last_review", ""))
        if last and (now - last).days > interval:
            issues.append(f"{name}: review overdue (>{interval}d)")

        if phi in ("full", "partial"):
            q = v.get("questionnaire") or {}
            missing = [k for k in SIG_LITE_KEYS if not q.get(k)]
            if missing:
                issues.append(f"{name}: questionnaire incomplete ({len(missing)} items)")

    if not issues:
        return "pass", f"{len(vendors)} vendor(s) current", []
    if len(issues) <= 2:
        return "warn", f"{len(issues)} vendor gap(s)", issues
    return "fail", f"{len(issues)} vendor gap(s)", issues


def _parse_date(value: str):
    if not value:
        return None
    try:
        return datetime.strptime(value.strip(), "%Y-%m-%d").date()
    except ValueError:
        return None
