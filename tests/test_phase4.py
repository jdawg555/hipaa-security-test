import json
from pathlib import Path

import pytest

from hipaa_audit.auditor_requests import add_message, create_request, get_request, init_db, list_requests
from hipaa_audit.policy_versions import list_versions, snapshot_policy
from hipaa_audit.prowler_crosswalk import collect_finding_statuses, rollup_requirements
from hipaa_audit.questionnaires import find_questionnaire_by_token, record_questionnaire_open, send_questionnaire
from hipaa_audit.vendors import add_vendor


def test_auditor_pbc_lifecycle(tmp_path):
    db = tmp_path / "compliance" / "auditor-requests.db"
    req = create_request(db, title="CloudTrail logs", control_ref="HIPAA-INT-001", due_date="2026-07-01")
    assert req["id"].startswith("PBC-")
    add_message(db, request_id=req["id"], author="auditor@firm.com", author_role="auditor", body="Please provide logs")
    add_message(db, request_id=req["id"], author="sec@org.com", author_role="org", body="Attached in ZIP")
    detail = get_request(db, req["id"])
    assert detail and len(detail["messages"]) == 2
    assert len(list_requests(db)) == 1


def test_policy_version_snapshot(tmp_path):
    pdir = tmp_path / "policies"
    pdir.mkdir()
    (pdir / "test.md").write_text("# v1")
    meta = snapshot_policy(pdir, "test.md", new_content="# v2 content", bump_version=True, summary="Major update")
    assert meta["version"] == "1.1"
    assert (pdir / "test.md").read_text() == "# v2 content"
    assert len(list_versions(pdir, "test.md")) >= 1


def test_prowler_crosswalk_rollup(tmp_path):
    prowler_dir = tmp_path / "evidence" / "prowler"
    prowler_dir.mkdir(parents=True)
    payload = [{"status": "FAIL", "check_id": "guardduty_is_enabled"}]
    (prowler_dir / "r.json").write_text(json.dumps(payload))
    statuses = collect_finding_statuses([prowler_dir / "r.json"])
    rollup = rollup_requirements(statuses)
    assert any(r["status"] == "fail" for r in rollup)


def test_questionnaire_token_tracking(tmp_path):
    vpath = tmp_path / "vendors.yaml"
    qpath = tmp_path / "q.yaml"
    vendor = add_vendor(vpath, name="Acme", phi_access="partial")
    entry = send_questionnaire(qpath, vpath, vendor_id=vendor["id"], contact="v@acme.com")
    assert entry and entry.get("portal_token")
    assert record_questionnaire_open(qpath, entry["portal_token"])
    found = find_questionnaire_by_token(qpath, entry["portal_token"])
    assert found and found.get("opened_at")


def test_prowler_crosswalk_check(tmp_path):
    from hipaa_audit.checks import integrations

    prowler_dir = tmp_path / "evidence" / "prowler"
    prowler_dir.mkdir(parents=True)
    (prowler_dir / "r.json").write_text(json.dumps([{"status": "FAIL", "check_id": "guardduty_is_enabled"}]))
    evidence = tmp_path / "out"
    evidence.mkdir()
    result = integrations.run(
        {"id": "x", "title": "crosswalk", "handler": "prowler_hipaa_crosswalk"},
        repo_path=tmp_path,
        config={"integrations": {"prowler": {"enabled": True}}},
        evidence_dir=evidence,
    )
    assert result.status.value == "fail"
