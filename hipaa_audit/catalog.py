from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from hipaa_audit.controls import PACKAGE_ROOT, load_controls

PROBO_CATALOG = PACKAGE_ROOT / "controls" / "probo-hipaa-catalog.json"


def load_probo_catalog() -> dict[str, Any]:
    if not PROBO_CATALOG.exists():
        return {"controls": []}
    return json.loads(PROBO_CATALOG.read_text())


def coverage_report() -> dict[str, Any]:
    probo = load_probo_catalog()
    ours = load_controls()
    our_ids = {c.id for c in ours}
    probo_ids = {p["id"] for p in probo.get("controls", [])}

    mapped = []
    unmapped_probo = []
    citations = [c.citation for c in ours]
    for p in probo.get("controls", []):
        pid = p["id"]
        slug = pid.replace("(", "-").replace(")", "").replace(".", "-")
        cid = f"HIPAA-PROBO-{slug}"
        cited = any(pid in cit or f"§{pid}" in cit for cit in citations)
        if cid in our_ids or cited:
            mapped.append(pid)
        else:
            unmapped_probo.append(pid)

    return {
        "probo_total": len(probo_ids),
        "hipaa_audit_controls": len(ours),
        "probo_mapped": len(mapped),
        "probo_unmapped": unmapped_probo,
        "coverage_pct": round(100 * len(mapped) / len(probo_ids), 1) if probo_ids else 0,
    }
