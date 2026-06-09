from pathlib import Path

import pytest

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


def test_jamf_adapter_missing_env():
    from hipaa_audit.platform.adapters.jamf import JamfAdapter

    result = JamfAdapter().test_connection({})
    assert not result.ok
    assert "Missing env" in result.message


def test_jamf_adapter_pro_api(monkeypatch):
    pytest.importorskip("httpx")
    from hipaa_audit.platform.adapters.jamf import JamfAdapter

    monkeypatch.setenv("JAMF_URL", "https://jamf.example.com")
    monkeypatch.setenv("JAMF_USER", "api")
    monkeypatch.setenv("JAMF_PASSWORD", "secret")

    class FakeResponse:
        status_code = 200

        def json(self):
            return {"token": "test-token"}

    def fake_post(url, **kwargs):
        assert url.endswith("/api/v1/auth")
        return FakeResponse()

    import httpx

    monkeypatch.setattr(httpx, "post", fake_post)
    result = JamfAdapter().test_connection({})
    assert result.ok
    assert "Jamf Pro API" in result.message


def test_intune_adapter_missing_env():
    from hipaa_audit.platform.adapters.intune import IntuneAdapter

    result = IntuneAdapter().test_connection({})
    assert not result.ok
    assert "Missing env" in result.message


def test_registry_personnel_register(tmp_path):
    from hipaa_audit.platform.adapters.registry import test_integration_connection

    (tmp_path / "compliance").mkdir()
    (tmp_path / "compliance" / "acknowledgments.yaml").write_text("items: []\n")
    config = {"personnel": {"enabled": True, "register_path": "compliance/acknowledgments.yaml"}}
    result = test_integration_connection("personnel", config, repo_path=tmp_path)
    assert result.ok
