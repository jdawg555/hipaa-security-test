from pathlib import Path

import yaml

from hipaa_audit.auditor_portal import publish_auditor_portal
from hipaa_audit.frameworks import iso27001_report
from hipaa_audit.questionnaires import find_questionnaire, import_response, send_questionnaire
from hipaa_audit.vendor_portal import publish_vendor_portal

ROOT = Path(__file__).resolve().parent.parent


def test_iso27001_loads_when_enabled():
    report = iso27001_report({"frameworks": {"iso27001": True}})
    assert report["iso27001_controls"] == 10
    assert report["total_controls"] >= 87


def test_auditor_portal_publish(tmp_path):
    report = tmp_path / "evidence" / "latest" / "audit-report.json"
    report.parent.mkdir(parents=True)
    report.write_text(
        """{
          "org_name": "Audit Co",
          "generated_at": "2026-05-28T12:00:00Z",
          "summary": {"pass": 5, "fail": 1},
          "posture": {"score": 91},
          "controls": [{"id": "HIPAA-164.308-a1", "title": "SRA", "status": "pass", "checks": [{"message": "ok"}]}]
        }"""
    )
    (tmp_path / "policies").mkdir()
    (tmp_path / "policies" / "hipaa-security-policy.md").write_text("# P")
    out = publish_auditor_portal(
        repo_path=tmp_path,
        config={"org_name": "Audit Co"},
        report_json=report,
        access_passphrase="test-secret",
    )
    html = out.read_text()
    assert "Auditor Portal" in html
    assert "Auditor access" in html


def test_vendor_portal_and_import(tmp_path):
    vendors = tmp_path / "compliance" / "vendors.yaml"
    vendors.parent.mkdir(parents=True)
    vendors.write_text((ROOT / "compliance" / "vendors.example.yaml").read_text())
    q_path = tmp_path / "compliance" / "vendor-questionnaires.yaml"
    entry = send_questionnaire(q_path, vendors, vendor_id="VND-001", contact="v@example.com")
    found = find_questionnaire(q_path, entry["id"])
    assert found is not None
    out = publish_vendor_portal(
        repo_path=tmp_path,
        config={"org_name": "Org", "vendors": {"portal_dir": "compliance/vendor-portals"}},
        questionnaire=found,
    )
    assert out.exists()
    response = tmp_path / f"{entry['id']}-response.yaml"
    response.write_text(
        yaml.dump(
            {
                "questionnaire_id": entry["id"],
                "vendor_id": "VND-001",
                "reviewer": "Vendor Sec",
                "responses": {k: True for k in [
                    "soc2_or_iso", "encryption_at_rest", "encryption_in_transit", "mfa_enforced",
                    "access_logging", "incident_notification", "subprocessors_disclosed", "data_retention_defined",
                ]},
            }
        )
    )
    assert import_response(q_path, vendors, entry["id"], response)
