from pathlib import Path

import yaml

from hipaa_audit.apps import assess_inventory, link_app, load_inventory, merge_discovered
from hipaa_audit.export_auditor import build_auditor_bundle
from hipaa_audit.trust_center import publish_trust_center

ROOT = Path(__file__).resolve().parent.parent


def test_saas_inventory_warns_on_unlinked(tmp_path):
    inv = tmp_path / "compliance" / "saas-inventory.yaml"
    vendors = tmp_path / "compliance" / "vendors.yaml"
    inv.parent.mkdir(parents=True)
    inv.write_text((ROOT / "compliance" / "saas-inventory.example.yaml").read_text())
    vendors.write_text((ROOT / "compliance" / "vendors.example.yaml").read_text())
    tier, _, issues = assess_inventory(inv, vendors, {"saas_inventory": {"max_discovery_age_days": 365}})
    assert tier == "warn"
    assert issues


def test_saas_inventory_pass_when_linked(tmp_path):
    inv = tmp_path / "compliance" / "saas-inventory.yaml"
    vendors = tmp_path / "compliance" / "vendors.yaml"
    inv.parent.mkdir(parents=True)
    inv.write_text((ROOT / "compliance" / "saas-inventory.example.yaml").read_text())
    vendors.write_text((ROOT / "compliance" / "vendors.example.yaml").read_text())
    link_app(inv, "okta-0oa1slack", "VND-001", phi_risk="low")
    link_app(inv, "okta-0oa2github", "VND-001", phi_risk="low")
    tier, _, issues = assess_inventory(inv, vendors, {"saas_inventory": {"max_discovery_age_days": 365}})
    assert tier == "pass"
    assert not issues


def test_merge_discovered_preserves_vendor_links(tmp_path):
    inv = tmp_path / "saas-inventory.yaml"
    inv.write_text((ROOT / "compliance" / "saas-inventory.example.yaml").read_text())
    link_app(inv, "okta-0oa3ehr", "VND-002")
    merge_discovered(
        inv,
        [{"id": "okta-0oa3ehr", "name": "Example EHR SaaS", "provider": "okta", "status": "active"}],
        source="okta",
    )
    data = load_inventory(inv)
    ehr = next(a for a in data["apps"] if a["id"] == "okta-0oa3ehr")
    assert ehr["vendor_id"] == "VND-002"


def test_trust_center_publish(tmp_path):
    report = tmp_path / "evidence" / "latest" / "audit-report.json"
    report.parent.mkdir(parents=True)
    report.write_text(
        """{
          "org_name": "Test Org",
          "generated_at": "2026-05-28T12:00:00Z",
          "summary": {"pass": 10, "fail": 1, "warn": 2},
          "posture": {"score": 88.5}
        }"""
    )
    certs = tmp_path / "compliance" / "certifications.yaml"
    certs.parent.mkdir(parents=True)
    certs.write_text((ROOT / "compliance" / "certifications.example.yaml").read_text())
    (tmp_path / "policies").mkdir()
    (tmp_path / "policies" / "hipaa-security-policy.md").write_text("# Policy")
    out = publish_trust_center(
        repo_path=tmp_path,
        config={
            "org_name": "Test Org",
            "trust_center": {"certifications_path": "compliance/certifications.yaml"},
            "policy_dir": "policies",
        },
        report_json=report,
    )
    assert out.exists()
    html = out.read_text()
    assert "Test Org Trust Center" in html
    assert "88.5%" in html


def test_auditor_bundle(tmp_path):
    latest = tmp_path / "evidence" / "latest"
    latest.mkdir(parents=True)
    (latest / "audit-report.json").write_text('{"org_name": "X"}')
    (tmp_path / "policies").mkdir()
    (tmp_path / "policies" / "hipaa-security-policy.md").write_text("# P")
    out = tmp_path / "evidence" / "auditor.zip"
    build_auditor_bundle(tmp_path, out, config={"org_name": "X"})
    assert out.exists()
    assert out.stat().st_size > 100


def test_apps_check_skips_when_disabled(tmp_path):
    from hipaa_audit.checks import apps as apps_checks

    result = apps_checks.run(
        {"id": "saas-inventory-tracked", "title": "SaaS", "handler": "saas_inventory_tracked"},
        repo_path=tmp_path,
        config={},
        evidence_dir=tmp_path / "evidence",
    )
    assert result.status.value == "skip"
