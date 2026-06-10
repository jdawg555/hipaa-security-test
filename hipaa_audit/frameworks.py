from __future__ import annotations

from hipaa_audit.controls import load_controls

_FRAMEWORK_PREFIXES = ("SOC2-", "ISO27001-", "HITRUST-", "PCI-")


def _hipaa_only(controls: list) -> list:
    return [c for c in controls if not c.id.startswith(_FRAMEWORK_PREFIXES)]


def soc2_report(config: dict | None = None) -> dict:
    controls = load_controls(config=config or {})
    soc2 = [c for c in controls if c.id.startswith("SOC2-")]
    mapped_cc = sorted({m for c in soc2 for m in c.soc2_mapping})
    return {
        "soc2_controls": len(soc2),
        "hipaa_controls": len(_hipaa_only(controls)),
        "total_controls": len(controls),
        "soc2_criteria_mapped": mapped_cc,
        "soc2_criteria_count": len(mapped_cc),
        "enabled": bool((config or {}).get("frameworks", {}).get("soc2", False)),
    }


def iso27001_report(config: dict | None = None) -> dict:
    controls = load_controls(config=config or {})
    iso = [c for c in controls if c.id.startswith("ISO27001-")]
    annex = sorted({c.citation for c in iso if c.citation})
    return {
        "iso27001_controls": len(iso),
        "hipaa_controls": len(_hipaa_only(controls)),
        "total_controls": len(controls),
        "annex_a_mapped": annex,
        "annex_a_count": len(annex),
        "enabled": bool((config or {}).get("frameworks", {}).get("iso27001", False)),
    }


def hitrust_report(config: dict | None = None) -> dict:
    controls = load_controls(config=config or {})
    hitrust = [c for c in controls if c.id.startswith("HITRUST-")]
    categories = sorted({c.citation for c in hitrust if c.citation})
    return {
        "hitrust_controls": len(hitrust),
        "hipaa_controls": len(_hipaa_only(controls)),
        "total_controls": len(controls),
        "categories_mapped": categories,
        "enabled": bool((config or {}).get("frameworks", {}).get("hitrust", False)),
    }


def pci_report(config: dict | None = None) -> dict:
    controls = load_controls(config=config or {})
    pci = [c for c in controls if c.id.startswith("PCI-")]
    reqs = sorted({c.citation for c in pci if c.citation})
    return {
        "pci_controls": len(pci),
        "hipaa_controls": len(_hipaa_only(controls)),
        "total_controls": len(controls),
        "requirements_mapped": reqs,
        "enabled": bool((config or {}).get("frameworks", {}).get("pci", False)),
    }
