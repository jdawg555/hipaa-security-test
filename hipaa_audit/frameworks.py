from __future__ import annotations

from hipaa_audit.controls import load_controls


def soc2_report(config: dict | None = None) -> dict:
    controls = load_controls(config=config or {})
    soc2 = [c for c in controls if c.id.startswith("SOC2-")]
    hipaa = [c for c in controls if not c.id.startswith("SOC2-")]
    mapped_cc = sorted({m for c in soc2 for m in c.soc2_mapping})
    return {
        "soc2_controls": len(soc2),
        "hipaa_controls": len(hipaa),
        "total_controls": len(controls),
        "soc2_criteria_mapped": mapped_cc,
        "soc2_criteria_count": len(mapped_cc),
        "enabled": bool((config or {}).get("frameworks", {}).get("soc2", False)),
    }
