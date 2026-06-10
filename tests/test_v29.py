import json
import zipfile
from pathlib import Path

from hipaa_audit.export_auditor import build_auditor_bundle
from hipaa_audit.oauth_connect import authorize_url, new_oauth_state, oauth_available
from hipaa_audit.platform.adapters.bamboohr import BambooHRAdapter
from hipaa_audit.trust_center import publish_trust_center


def test_bamboohr_adapter_missing_credentials():
    result = BambooHRAdapter().test_connection({})
    assert not result.ok
    assert "BAMBOOHR" in result.message


def test_bamboohr_discover(tmp_path, monkeypatch):
    class FakeBamboo:
        def discover(self, config):
            return [{"id": "42", "email": "a@example.com", "active": True, "source": "bamboohr"}]

    monkeypatch.setattr(
        "hipaa_audit.platform.adapters.bamboohr.BambooHRAdapter.discover",
        FakeBamboo().discover,
    )
    from hipaa_audit.personnel import sync_workforce_hris

    ack = tmp_path / "compliance" / "acknowledgments.yaml"
    ack.parent.mkdir(parents=True)
    ack.write_text("workforce: []\n")
    count = sync_workforce_hris(ack, FakeBamboo().discover({}))
    assert count == 1


def test_trust_center_public_url(tmp_path):
    report = tmp_path / "evidence" / "latest" / "audit-report.json"
    report.parent.mkdir(parents=True)
    report.write_text(
        json.dumps(
            {
                "org_name": "Test Org",
                "generated_at": "2026-05-28T12:00:00Z",
                "summary": {"pass": 10, "fail": 0, "warn": 0},
                "posture": {"score": 90},
            }
        )
    )
    out = publish_trust_center(
        repo_path=tmp_path,
        config={
            "trust_center": {
                "public_url": "https://trust.example.com",
                "certifications_path": "compliance/certifications.yaml",
            },
            "policy_dir": "policies",
        },
        report_json=report,
    )
    html = out.read_text()
    assert 'rel="canonical" href="https://trust.example.com"' in html
    assert "https://trust.example.com" in html


def test_auditor_bundle_trust_public_url(tmp_path):
    (tmp_path / "evidence" / "latest").mkdir(parents=True)
    (tmp_path / "evidence" / "latest" / "audit-report.json").write_text("{}")
    out = tmp_path / "evidence" / "latest" / "auditor-bundle.zip"
    build_auditor_bundle(
        tmp_path,
        out,
        config={"org_name": "Test", "trust_center": {"public_url": "https://trust.example.com"}},
    )
    with zipfile.ZipFile(out) as zf:
        manifest = json.loads(zf.read("auditor-manifest.json"))
    assert manifest["trust_center_public_url"] == "https://trust.example.com"


def test_gitlab_oauth_available():
    secrets = {
        "gitlab_oauth_client_id": "cid",
        "gitlab_oauth_client_secret": "csec",
    }
    assert oauth_available("gitlab", secrets=secrets)
    url = authorize_url(
        "gitlab",
        redirect_uri="http://127.0.0.1:8787/integrations/oauth/gitlab/callback",
        state=new_oauth_state(),
        secrets=secrets,
    )
    assert url and "gitlab.com/oauth/authorize" in url
