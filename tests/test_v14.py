import json
from pathlib import Path

from hipaa_audit.controls import load_config
from hipaa_audit.engine import run_audit
from hipaa_audit.export_probo import to_probo_bundle
from hipaa_audit.posture import compute_posture, record_history
from hipaa_audit.tasks import complete_task, sync_from_report

ROOT = Path(__file__).resolve().parent.parent


def test_posture_score_computed(tmp_path):
    cfg = load_config(ROOT / "hipaa-audit.example.yaml")
    report = run_audit(ROOT, config=cfg, evidence_dir=tmp_path)
    posture = compute_posture(report)
    assert "score" in posture
    assert 0 <= posture["score"] <= 100
    snap = record_history(report, tmp_path)
    assert snap.exists()
    assert (tmp_path / "evidence" / "history" / "posture.jsonl").exists()


def test_tasks_sync_and_complete(tmp_path):
    cfg = load_config(ROOT / "hipaa-audit.example.yaml")
    report = run_audit(ROOT, config=cfg, evidence_dir=tmp_path)
    tasks_path = tmp_path / "compliance" / "tasks.yaml"
    created = sync_from_report(report, tasks_path, default_owner="test@example.com")
    # May be empty if no failures — still valid
    assert isinstance(created, list)
    if created:
        assert complete_task(tasks_path, created[0]["id"])


def test_probo_export_shape(tmp_path):
    cfg = load_config(ROOT / "hipaa-audit.example.yaml")
    report = run_audit(ROOT, config=cfg, evidence_dir=tmp_path)
    bundle = to_probo_bundle(report)
    assert bundle["format"] == "hipaa-audit-probo-v1"
    assert bundle["framework"] == "HIPAA Security Rule"
    assert len(bundle["measures"]) == len(report.controls)
    assert "posture_score" in bundle
