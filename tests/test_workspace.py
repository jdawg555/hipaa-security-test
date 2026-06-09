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
    r = client.post("/policies/edit/test-policy.md", data={"content": "# New content", "summary": "test"})
    assert r.status_code == 303
    assert "New content" in policy.read_text()
    assert (tmp_path / "policies" / ".history" / "manifest.yaml").exists()


def test_pbc_queue(tmp_path):
    app = create_app(tmp_path)
    client = TestClient(app, follow_redirects=False)
    client.post("/onboarding", data={"org_name": "Test", "bootstrap": "yes"})
    r = client.post(
        "/audits/pbc/create",
        data={"title": "IAM user list", "control_ref": "HIPAA-164", "due_date": "2026-08-01"},
    )
    assert r.status_code == 303
    r = client.get("/audits", follow_redirects=True)
    assert "IAM user list" in r.text


def test_vendor_portal_submit(tmp_path):
    app = create_app(tmp_path)
    client = TestClient(app, follow_redirects=False)
    client.post("/onboarding", data={"org_name": "Test", "bootstrap": "yes"})
    from hipaa_audit.questionnaires import send_questionnaire
    from hipaa_audit.vendors import add_vendor

    vpath = tmp_path / "compliance" / "vendors.yaml"
    qpath = tmp_path / "compliance" / "vendor-questionnaires.yaml"
    vendor = add_vendor(vpath, name="Acme")
    entry = send_questionnaire(qpath, vpath, vendor_id=vendor["id"], contact="v@test.com")
    token = entry["portal_token"]
    r = client.post(
        f"/portals/vendor/{token}",
        data={
            "soc2_or_iso": "true",
            "encryption_at_rest": "true",
            "encryption_in_transit": "true",
            "mfa_enforced": "true",
            "access_logging": "true",
            "incident_notification": "true",
            "subprocessors_disclosed": "true",
            "data_retention_defined": "true",
            "reviewer": "Vendor Sec",
        },
    )
    assert r.status_code == 303
    import yaml

    data = yaml.safe_load(qpath.read_text())
    assert data["questionnaires"][0]["status"] == "responded"


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


def test_ack_portal(tmp_path):
    app = create_app(tmp_path)
    client = TestClient(app, follow_redirects=False)
    client.post("/onboarding", data={"org_name": "Test", "bootstrap": "yes"})
    ack = tmp_path / "compliance" / "acknowledgments.yaml"
    ack.write_text(
        "policies:\n"
        "  - policy: hipaa-security-policy.md\n"
        "    version: '1.0'\n"
        "workforce:\n"
        "  - id: EMP001\n"
        "    ack_token: testtoken123\n"
        "acknowledgments: []\n"
    )
    r = client.get("/portals/ack/testtoken123", follow_redirects=True)
    assert r.status_code == 200
    assert "hipaa-security-policy.md" in r.text
    r = client.post(
        "/portals/ack/testtoken123",
        data={"policy": "hipaa-security-policy.md", "version": "1.0"},
    )
    assert r.status_code == 303
    import yaml

    data = yaml.safe_load(ack.read_text())
    assert data["acknowledgments"][0]["employee_id"] == "EMP001"


def test_pbc_attachment_upload(tmp_path):
    app = create_app(tmp_path)
    client = TestClient(app, follow_redirects=False)
    client.post("/onboarding", data={"org_name": "Test", "bootstrap": "yes"})
    client.post("/audits/pbc/create", data={"title": "Logs", "control_ref": "HIPAA", "due_date": "2026-09-01"})
    from hipaa_audit.auditor_requests import list_requests

    req_id = list_requests(tmp_path / "compliance" / "auditor-requests.db")[0]["id"]
    r = client.post(
        f"/audits/pbc/{req_id}/message",
        data={"author": "sec@test.com", "body": "See attached"},
        files={"file": ("proof.txt", b"evidence", "text/plain")},
    )
    assert r.status_code == 303
    attach_dir = tmp_path / "compliance" / "pbc-attachments" / req_id
    assert (attach_dir / "proof.txt").exists()


def test_policy_diff_route(tmp_path):
    app = create_app(tmp_path)
    client = TestClient(app, follow_redirects=False)
    client.post("/onboarding", data={"org_name": "Test", "bootstrap": "yes"})
    policy = tmp_path / "policies" / "diff-policy.md"
    policy.write_text("# Before")
    client.post(
        "/policies/edit/diff-policy.md",
        data={"content": "# After", "summary": "change", "bump_version": "on"},
    )
    r = client.get("/policies/diff/diff-policy.md", follow_redirects=True)
    assert r.status_code == 200
    assert "diff" in r.text.lower() or "After" in r.text


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
