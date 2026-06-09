from __future__ import annotations

import csv
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml


def load_devices(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"devices": []}
    return yaml.safe_load(path.read_text()) or {"devices": []}


def save_devices(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.dump(data, sort_keys=False, default_flow_style=False))


def import_devices_csv(path: Path, csv_path: Path) -> int:
    data = load_devices(path)
    existing = {d.get("id"): d for d in data.get("devices", [])}
    count = 0
    with csv_path.open(newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            owner = (row.get("owner") or row.get("email") or "").strip()
            if not owner:
                continue
            device_id = row.get("device_id") or row.get("id") or f"DEV-{owner.split('@')[0]}"
            device = {
                "id": device_id,
                "owner": owner,
                "platform": (row.get("platform") or row.get("os") or "unknown").lower(),
                "mdm": (row.get("mdm") or row.get("source") or "manual").lower(),
                "encrypted": _bool(row.get("encrypted")),
                "screen_lock": _bool(row.get("screen_lock") or row.get("screenlock")),
                "os_version": (row.get("os_version") or row.get("version") or "").strip(),
                "last_seen": (row.get("last_seen") or row.get("last_sync") or "").strip(),
            }
            existing[device_id] = device
            count += 1
    data["devices"] = list(existing.values())
    data["imported_at"] = datetime.now(UTC).strftime("%Y-%m-%d")
    save_devices(path, data)
    return count


def assess_devices(path: Path, config: dict[str, Any]) -> tuple[str, str, list[str]]:
    data = load_devices(path)
    devices = data.get("devices", [])
    if not devices:
        return "manual", "No device inventory — hipaa-audit devices import <csv>", []

    cfg = config.get("devices", {})
    max_stale = int(cfg.get("max_last_seen_days", 30))
    now = datetime.now(UTC).date()
    issues: list[str] = []

    for d in devices:
        label = d.get("id", d.get("owner", "?"))
        if not d.get("encrypted"):
            issues.append(f"{label}: disk encryption not confirmed")
        if not d.get("screen_lock"):
            issues.append(f"{label}: screen lock not confirmed")
        last = _parse_date(d.get("last_seen", ""))
        if last and (now - last).days > max_stale:
            issues.append(f"{label}: stale MDM sync ({(now - last).days}d)")

    if not issues:
        return "pass", f"{len(devices)} device(s) compliant", []
    if len(issues) <= 3:
        return "warn", f"{len(issues)} device gap(s)", issues
    return "fail", f"{len(issues)} device gap(s)", issues[:5]


def device_csv_template(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "device_id,owner,platform,mdm,encrypted,screen_lock,os_version,last_seen\n"
        "DEV-001,clinician@example.com,macos,jamf,true,true,14.5,2026-05-20\n"
        "DEV-002,admin@example.com,windows,intune,true,true,11,2026-05-22\n"
    )
    return path


def _bool(value: Any) -> bool:
    if value is None:
        return False
    return str(value).strip().lower() in ("1", "true", "yes", "y")


def _parse_date(value: str):
    if not value:
        return None
    for fmt in ("%Y-%m-%d", "%m/%d/%Y"):
        try:
            return datetime.strptime(value.strip(), fmt).date()
        except ValueError:
            continue
    return None
