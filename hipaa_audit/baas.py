from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml


def load_baas(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"baas": []}
    return yaml.safe_load(path.read_text()) or {"baas": []}


def save_baas(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.dump(data, sort_keys=False, default_flow_style=False))


def add_baa(
    path: Path,
    *,
    vendor_id: str,
    vendor_name: str,
    effective_date: str,
    expiry_date: str,
    status: str = "active",
    document_path: str = "",
    signed_by: str = "",
    notes: str = "",
) -> dict[str, Any]:
    data = load_baas(path)
    seq = len(data.get("baas", [])) + 1
    baa = {
        "id": f"BAA-{seq:03d}",
        "vendor_id": vendor_id,
        "vendor_name": vendor_name,
        "effective_date": effective_date,
        "expiry_date": expiry_date,
        "status": status,
        "document_path": document_path,
        "signed_by": signed_by,
        "notes": notes,
        "created_at": datetime.now(UTC).strftime("%Y-%m-%d"),
    }
    data.setdefault("baas", []).append(baa)
    save_baas(path, data)
    return baa


def update_baa(path: Path, baa_id: str, **fields: Any) -> bool:
    data = load_baas(path)
    for baa in data.get("baas", []):
        if baa.get("id") != baa_id:
            continue
        for key, value in fields.items():
            if value is not None and key in baa:
                baa[key] = value
        save_baas(path, data)
        return True
    return False


def delete_baa(path: Path, baa_id: str) -> bool:
    data = load_baas(path)
    before = len(data.get("baas", []))
    data["baas"] = [b for b in data.get("baas", []) if b.get("id") != baa_id]
    if len(data["baas"]) == before:
        return False
    save_baas(path, data)
    return True


def assess_baas(
    baas_path: Path,
    vendors_path: Path,
    *,
    expiry_warning_days: int = 30,
) -> tuple[str, str, list[str]]:
    data = load_baas(baas_path)
    baas = data.get("baas", [])
    if not baas:
        return "manual", "No structured BAA register — add compliance/baas.yaml", []

    now = datetime.now(UTC).date()
    warn_cutoff = now + timedelta(days=expiry_warning_days)
    issues: list[str] = []

    active_vendor_ids = {b.get("vendor_id") for b in baas if b.get("status") == "active"}
    for baa in baas:
        expiry = _parse_date(baa.get("expiry_date", ""))
        if expiry and expiry < now:
            issues.append(f"{baa.get('vendor_name', baa.get('id'))}: BAA expired {baa.get('expiry_date')}")
        elif expiry and expiry <= warn_cutoff:
            issues.append(f"{baa.get('vendor_name', baa.get('id'))}: BAA expires {baa.get('expiry_date')}")

    if vendors_path.exists():
        import yaml as yaml_mod

        vendors = (yaml_mod.safe_load(vendors_path.read_text()) or {}).get("vendors", [])
        for v in vendors:
            phi = (v.get("phi_access") or "none").lower()
            if phi in ("full", "partial") and v.get("id") not in active_vendor_ids:
                if not v.get("baa_executed"):
                    issues.append(f"{v.get('name')}: PHI vendor without active BAA")

    if not issues:
        return "pass", f"{len(baas)} BAA(s) tracked", []
    if len(issues) <= 2:
        return "warn", "; ".join(issues[:3]), issues
    return "fail", f"{len(issues)} BAA gap(s)", issues


def expiring_baas(path: Path, *, within_days: int = 30) -> list[dict[str, Any]]:
    data = load_baas(path)
    now = datetime.now(UTC).date()
    cutoff = now + timedelta(days=within_days)
    alerts: list[dict[str, Any]] = []
    for baa in data.get("baas", []):
        if baa.get("status") != "active":
            continue
        expiry = _parse_date(baa.get("expiry_date", ""))
        if not expiry:
            continue
        if expiry < now:
            alerts.append({**baa, "alert": "expired"})
        elif expiry <= cutoff:
            alerts.append({**baa, "alert": "expiring"})
    return alerts


def _parse_date(value: str):
    if not value:
        return None
    try:
        return datetime.strptime(value.strip(), "%Y-%m-%d").date()
    except ValueError:
        return None
