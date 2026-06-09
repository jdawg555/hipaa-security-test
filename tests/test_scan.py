from pathlib import Path

from hipaa_audit.controls import load_config
from hipaa_audit.engine import run_audit
from hipaa_audit.report import write_reports

ROOT = Path(__file__).resolve().parent.parent


def test_self_audit_runs(tmp_path):
    cfg = load_config(ROOT / "hipaa-audit.example.yaml")
    cfg["org_name"] = "hipaa-security-test"
    report = run_audit(ROOT, config=cfg, evidence_dir=tmp_path)
    assert len(report.controls) >= 76
    paths = write_reports(report, tmp_path)
    assert paths["json"].exists()
    assert paths["html"].exists()
    # Self-audit should pass policy library (bundled policies)
    policy_results = [cr for cr in report.controls if cr.control.id == "HIPAA-164.316"]
    assert policy_results
    assert policy_results[0].status.value in ("pass", "warn")
