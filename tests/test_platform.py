from pathlib import Path

from hipaa_audit.platform.parity import load_capabilities, load_integrations, parity_report
from hipaa_audit.platform.scaffold import scaffold_integration, scaffold_module


def test_capabilities_loads():
    data = load_capabilities()
    assert data.get("capabilities")
    assert any(c["id"] == "P-01" for c in data["capabilities"])


def test_integrations_registry():
    reg = load_integrations()
    ids = {i["id"] for i in reg.get("integrations", [])}
    assert "aws" in ids
    assert "jamf" in ids


def test_parity_report_coverage():
    report = parity_report()
    assert report["total"] >= 20
    assert "coverage_pct" in report
    assert report["by_status"].get("shipped", 0) >= 3


def test_scaffold_module(tmp_path):
    from hipaa_audit.controls import PACKAGE_ROOT

    name = "scaffold_probe_xyz"
    scaffold_module(tmp_path, name)
    assert (PACKAGE_ROOT / "hipaa_audit" / "checks" / f"{name}.py").exists()
    assert (PACKAGE_ROOT / "hipaa_audit" / f"{name}.py").exists()
    assert (tmp_path / "compliance" / f"{name}.example.yaml").exists()
    assert (tmp_path / "platform" / "scaffold_output.yaml").exists()
    for path in (
        PACKAGE_ROOT / "hipaa_audit" / "checks" / f"{name}.py",
        PACKAGE_ROOT / "hipaa_audit" / f"{name}.py",
    ):
        path.unlink(missing_ok=True)


def test_scaffold_integration(tmp_path):
    from hipaa_audit.controls import PACKAGE_ROOT

    created = scaffold_integration(tmp_path, "jamf")
    assert (tmp_path / "platform" / "scaffold-jamf.yaml").exists()
    assert (PACKAGE_ROOT / "hipaa_audit" / "platform" / "adapters" / "jamf.py").exists()
