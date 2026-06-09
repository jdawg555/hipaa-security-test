from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from hipaa_audit.models import Control, ControlType

PACKAGE_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONTROLS = PACKAGE_ROOT / "controls" / "hipaa-security-rule.yaml"


def load_controls(path: Path | None = None) -> list[Control]:
    controls_path = path or DEFAULT_CONTROLS
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


def load_config(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return yaml.safe_load(path.read_text()) or {}
