from pathlib import Path

import pytest

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from hipaa_audit.workspace.server import create_app


def test_onboarding_and_dashboard(tmp_path):
    app = create_app(tmp_path)
    client = TestClient(app, follow_redirects=False)
    r = client.get("/")
    assert r.status_code == 302
    assert "/onboarding" in r.headers["location"]
    r = client.post("/onboarding", data={"org_name": "Test Org", "bootstrap": "yes"})
    assert r.status_code == 303
    assert (tmp_path / "hipaa-audit.yaml").exists()
    assert (tmp_path / "policies").is_dir()
    r = client.get("/", follow_redirects=True)
    assert r.status_code == 200
    assert "Compliance dashboard" in r.text


def test_integrations_toggle(tmp_path):
    app = create_app(tmp_path)
    client = TestClient(app, follow_redirects=False)
    client.post("/onboarding", data={"org_name": "Test", "bootstrap": "yes"})
    r = client.post("/integrations/toggle", data={"integration_id": "aws", "enabled": "true"})
    assert r.status_code == 303
    import yaml

    cfg = yaml.safe_load((tmp_path / "hipaa-audit.yaml").read_text())
    assert cfg["aws"]["enabled"] is True


def test_api_status(tmp_path):
    app = create_app(tmp_path)
    client = TestClient(app)
    client.post("/onboarding", data={"org_name": "Test", "bootstrap": "yes"})
    r = client.get("/api/status")
    assert r.status_code == 200
    assert "version" in r.json()
