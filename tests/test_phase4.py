import json
from pathlib import Path

import pytest

from hipaa_audit.auditor_requests import add_message, create_request, get_request, init_db, list_requests
from hipaa_audit.baas import add_baa, expiring_baas
from hipaa_audit.pbc_attachments import list_attachments, save_attachment
from hipaa_audit.personnel import ensure_workforce_tokens, find_worker_by_token, record_acknowledgment
from hipaa_audit.policy_versions import list_versions, snapshot_policy, sync_policy_version_to_acks
from hipaa_audit.prowler_crosswalk import collect_finding_statuses, load_crosswalk, rollup_requirements
from hipaa_audit.questionnaires import (
    find_questionnaire_by_token,
    mark_reminder_sent,
    questionnaires_needing_reminder,
    record_questionnaire_open,
    send_questionnaire,
)
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


def test_pbc_attachment_save(tmp_path):
    req_id = "PBC-001"
    rel = save_attachment(tmp_path, req_id, "evidence.pdf", b"%PDF-1.4")
    assert "pbc-attachments" in rel
    files = list_attachments(tmp_path, req_id)
    assert len(files) == 1
    assert files[0].name == "evidence.pdf"


def test_workforce_ack_portal(tmp_path):
    ack = tmp_path / "ack.yaml"
    ack.write_text(
        "policies:\n"
        "  - policy: hipaa-security-policy.md\n"
        "    version: '1.1'\n"
        "workforce:\n"
        "  - id: EMP001\n"
        "    active: true\n"
        "acknowledgments: []\n"
    )
    data = ensure_workforce_tokens(ack)
    token = data["workforce"][0]["ack_token"]
    worker = find_worker_by_token(ack, token)
    assert worker
    record_acknowledgment(ack, employee_id="EMP001", policy="hipaa-security-policy.md", version="1.1")
    import yaml

    saved = yaml.safe_load(ack.read_text())
    assert saved["acknowledgments"][0]["employee_id"] == "EMP001"


def test_policy_version_sync_to_acks(tmp_path):
    ack = tmp_path / "ack.yaml"
    ack.write_text("policies:\n  - policy: test.md\n    version: '1.0'\nacknowledgments: []\n")
    sync_policy_version_to_acks(ack, "test.md", "1.2")
    import yaml

    data = yaml.safe_load(ack.read_text())
    assert data["policies"][0]["version"] == "1.2"


def test_questionnaire_reminder_window(tmp_path):
    from datetime import UTC, datetime, timedelta

    qpath = tmp_path / "q.yaml"
    due = (datetime.now(UTC) + timedelta(days=3)).strftime("%Y-%m-%d")
    qpath.write_text(
        "questionnaires:\n"
        "  - id: QNR-001\n"
        "    status: pending\n"
        f"    due_date: {due}\n"
        "    contact: v@test.com\n"
    )
    pending = questionnaires_needing_reminder(qpath)
    assert len(pending) == 1
    mark_reminder_sent(qpath, "QNR-001")
    assert not questionnaires_needing_reminder(qpath)


def test_expiring_baas(tmp_path):
    from datetime import UTC, datetime, timedelta

    bpath = tmp_path / "baas.yaml"
    soon = (datetime.now(UTC) + timedelta(days=10)).strftime("%Y-%m-%d")
    add_baa(bpath, vendor_id="V1", vendor_name="Acme", effective_date="2026-01-01", expiry_date=soon)
    alerts = expiring_baas(bpath, within_days=30)
    assert len(alerts) == 1
    assert alerts[0]["alert"] == "expiring"


def test_prowler_crosswalk_full_catalog():
    crosswalk = load_crosswalk()
    assert len(crosswalk.get("requirements", [])) >= 32


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
