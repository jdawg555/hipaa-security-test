from pathlib import Path

import yaml

from hipaa_audit.access_reviews import (
    assess_access_reviews,
    complete_campaign,
    record_decision,
    start_campaign,
)
from hipaa_audit.vendors import add_vendor, delete_vendor, update_vendor, assess_vendors, review_vendor

ROOT = Path(__file__).resolve().parent.parent


def test_vendor_register_pass(tmp_path):
    register = tmp_path / "compliance" / "vendors.yaml"
    register.parent.mkdir(parents=True)
    register.write_text((ROOT / "compliance" / "vendors.example.yaml").read_text())
    tier, msg, issues = assess_vendors(register, {})
    assert tier == "warn"
    assert issues


def test_vendor_add_and_review_pass(tmp_path):
    register = tmp_path / "compliance" / "vendors.yaml"
    vendor = add_vendor(register, name="Test SaaS", phi_access="partial", risk_tier="high", baa_executed=True)
    review_vendor(register, vendor["id"], {k: True for k in [
        "soc2_or_iso", "encryption_at_rest", "encryption_in_transit", "mfa_enforced",
        "access_logging", "incident_notification", "subprocessors_disclosed", "data_retention_defined",
    ]}, reviewer="security@example.com")
    tier, _, issues = assess_vendors(register, {})
    assert tier == "pass"
    assert not issues


def test_access_review_example_pass(tmp_path):
    register = tmp_path / "compliance" / "access-reviews.yaml"
    register.parent.mkdir(parents=True)
    register.write_text((ROOT / "compliance" / "access-reviews.example.yaml").read_text())
    tier, msg, issues = assess_access_reviews(register, {"access_reviews": {"max_campaign_age_days": 365}})
    assert tier == "pass"
    assert not issues


def test_access_review_campaign_flow(tmp_path):
    register = tmp_path / "compliance" / "access-reviews.yaml"
    campaign = start_campaign(
        register,
        name="Q1 review",
        owner="security@example.com",
        systems=[{"id": "github", "name": "GitHub", "owner": "eng@example.com"}],
        due_days=30,
    )
    record_decision(
        register,
        campaign_id=campaign["id"],
        system_id="github",
        principal="user@example.com",
        decision="retain",
        reviewer="eng@example.com",
    )
    complete_campaign(register, campaign["id"])
    tier, _, issues = assess_access_reviews(register, {"access_reviews": {"max_campaign_age_days": 120}})
    assert tier == "pass"
    assert not issues


def test_vendor_and_access_review_checks_skip_without_config(tmp_path):
    from hipaa_audit.checks import access_reviews as ar_checks
    from hipaa_audit.checks import vendors as vendor_checks

    cfg = {}
    v_result = vendor_checks.run(
        {"id": "vendor-register-current", "title": "Vendors", "handler": "vendor_register_current"},
        repo_path=tmp_path,
        config=cfg,
        evidence_dir=tmp_path / "evidence",
    )
    ar_result = ar_checks.run(
        {"id": "access-review-campaign", "title": "Access reviews", "handler": "access_review_campaign"},
        repo_path=tmp_path,
        config=cfg,
        evidence_dir=tmp_path / "evidence",
    )
    assert v_result.status.value == "skip"
    assert ar_result.status.value == "skip"
