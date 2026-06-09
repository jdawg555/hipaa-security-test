from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from hipaa_audit.controls import PACKAGE_ROOT

PLATFORM_ROOT = PACKAGE_ROOT / "platform"


def load_capabilities() -> dict[str, Any]:
    path = PLATFORM_ROOT / "capabilities.yaml"
    return yaml.safe_load(path.read_text()) or {}


def load_integrations() -> dict[str, Any]:
    path = PLATFORM_ROOT / "integrations_registry.yaml"
    return yaml.safe_load(path.read_text()) or {}


def parity_report(*, phase: int | None = None) -> dict[str, Any]:
    data = load_capabilities()
    caps = data.get("capabilities", [])
    if phase is not None:
        caps = [c for c in caps if c.get("phase") == phase]

    by_status: dict[str, int] = {}
    for c in caps:
        status = c.get("status", "planned")
        by_status[status] = by_status.get(status, 0) + 1

    total = len(caps)
    shipped = by_status.get("shipped", 0)
    partial = by_status.get("partial", 0)

    return {
        "capabilities": caps,
        "total": total,
        "by_status": by_status,
        "coverage_pct": round(100 * (shipped + 0.5 * partial) / total, 1) if total else 0,
        "phases": data.get("phases", {}),
    }
