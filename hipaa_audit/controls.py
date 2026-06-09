from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from hipaa_audit.models import Control, ControlType

PACKAGE_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONTROLS = PACKAGE_ROOT / "controls" / "hipaa-security-rule.yaml"


def _parse_controls_file(controls_path: Path) -> list[Control]:
    raw = yaml.safe_load(controls_path.read_text())
    controls: list[Control] = []
    for item in raw.get("controls", []):
        ctype = ControlType(item.get("type", "hybrid"))
        controls.append(
            Control(
                id=item["id"],
                title=item["title"],
                category=item.get("category", "general"),
                citation=item.get("citation", ""),
                description=item.get("description", ""),
                control_type=ctype,
                severity=item.get("severity", "required"),
                checks=item.get("checks", []),
                nist_csf=item.get("nist_csf", []),
                soc2_mapping=item.get("soc2_mapping", []),
            )
        )
    return controls


def load_controls(path: Path | None = None) -> list[Control]:
    if path is not None:
        return _parse_controls_file(path)

    catalog_files = sorted((PACKAGE_ROOT / "controls").glob("hipaa-*.yaml"))
    if not catalog_files:
        return _parse_controls_file(DEFAULT_CONTROLS)

    merged: list[Control] = []
    seen: set[str] = set()
    for catalog_path in catalog_files:
        for control in _parse_controls_file(catalog_path):
            if control.id in seen:
                continue
            seen.add(control.id)
            merged.append(control)
    return merged


def load_config(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return yaml.safe_load(path.read_text()) or {}
