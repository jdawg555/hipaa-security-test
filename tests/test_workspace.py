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


def test_tasks_page(tmp_path):
    app = create_app(tmp_path)
    client = TestClient(app, follow_redirects=False)
    client.post("/onboarding", data={"org_name": "Test", "bootstrap": "yes"})
    tasks_yaml = tmp_path / "compliance" / "tasks.yaml"
    tasks_yaml.write_text(
        "tasks:\n"
        "  - id: TASK-0001\n"
        "    control_id: HIPAA-01\n"
        "    title: Fix MFA\n"
        "    owner: sec@test.com\n"
        "    status: open\n"
        "    due_date: '2026-06-01'\n"
    )
    r = client.get("/tasks", follow_redirects=True)
    assert r.status_code == 200
    assert "TASK-0001" in r.text
    r = client.post("/tasks/done", data={"task_id": "TASK-0001"})
    assert r.status_code == 303
    import yaml

    data = yaml.safe_load(tasks_yaml.read_text())
    assert data["tasks"][0]["status"] == "done"


def test_integration_connection_test(tmp_path):
    app = create_app(tmp_path)
    client = TestClient(app, follow_redirects=False)
    client.post("/onboarding", data={"org_name": "Test", "bootstrap": "yes"})
    client.post("/integrations/toggle", data={"integration_id": "personnel", "enabled": "true"})
    r = client.post("/integrations/test", data={"integration_id": "personnel"})
    assert r.status_code == 303
    assert "test=" in r.headers["location"]
    import yaml

    cfg = yaml.safe_load((tmp_path / "hipaa-audit.yaml").read_text())
    assert "connection_tests" in cfg.get("workspace", {})
    assert "personnel" in cfg["workspace"]["connection_tests"]


def test_vendor_crud(tmp_path):
    app = create_app(tmp_path)
    client = TestClient(app, follow_redirects=False)
    client.post("/onboarding", data={"org_name": "Test", "bootstrap": "yes"})
    r = client.post(
        "/vendors/add",
        data={"name": "Acme SaaS", "phi_access": "partial", "risk_tier": "high", "baa_executed": "on"},
    )
    assert r.status_code == 303
    import yaml

    vendors = yaml.safe_load((tmp_path / "compliance" / "vendors.yaml").read_text())["vendors"]
    assert vendors[-1]["name"] == "Acme SaaS"
    vid = vendors[-1]["id"]
    client.post(
        "/vendors/update",
        data={
            "vendor_id": vid,
            "name": "Acme Updated",
            "phi_access": "full",
            "risk_tier": "high",
            "baa_executed": "on",
        },
    )
    vendors = yaml.safe_load((tmp_path / "compliance" / "vendors.yaml").read_text())["vendors"]
    assert any(v["name"] == "Acme Updated" for v in vendors)


def test_baas_page(tmp_path):
    app = create_app(tmp_path)
    client = TestClient(app, follow_redirects=False)
    client.post("/onboarding", data={"org_name": "Test", "bootstrap": "yes"})
    r = client.post(
        "/baas/add",
        data={
            "vendor_id": "VND-001",
            "vendor_name": "AWS",
            "effective_date": "2026-01-01",
            "expiry_date": "2028-01-01",
        },
    )
    assert r.status_code == 303
    r = client.get("/baas", follow_redirects=True)
    assert "BAA-001" in r.text or "AWS" in r.text


def test_policy_editor(tmp_path):
    app = create_app(tmp_path)
    client = TestClient(app, follow_redirects=False)
    client.post("/onboarding", data={"org_name": "Test", "bootstrap": "yes"})
    policy = tmp_path / "policies" / "test-policy.md"
    policy.write_text("# Old")
    r = client.post("/policies/edit/test-policy.md", data={"content": "# New content"})
    assert r.status_code == 303
    assert "New content" in policy.read_text()


def test_connect_wizard_saves_secrets(tmp_path):
    app = create_app(tmp_path)
    client = TestClient(app, follow_redirects=False)
    client.post("/onboarding", data={"org_name": "Test", "bootstrap": "yes"})
    r = client.post(
        "/integrations/connect/github",
        data={"github_token": "ghp_test_token_12345"},
    )
    assert r.status_code == 303
    import yaml

    secrets = yaml.safe_load((tmp_path / "compliance" / ".workspace-secrets.yaml").read_text())
    assert secrets.get("github_token") == "ghp_test_token_12345"


def test_access_review_campaign_builder(tmp_path):
    app = create_app(tmp_path)
    client = TestClient(app, follow_redirects=False)
    client.post("/onboarding", data={"org_name": "Test", "bootstrap": "yes"})
    r = client.post(
        "/access-reviews/start",
        data={
            "name": "Q3 review",
            "owner": "sec@test.com",
            "due_days": "14",
            "systems_text": "github|GitHub|eng@test.com",
        },
    )
    assert r.status_code == 303
    import yaml

    data = yaml.safe_load((tmp_path / "compliance" / "access-reviews.yaml").read_text())
    names = [c["name"] for c in data["campaigns"]]
    assert "Q3 review" in names
    r = client.get("/access-reviews", follow_redirects=True)
    assert "Q3 review" in r.text
