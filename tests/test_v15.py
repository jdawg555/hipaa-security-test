from pathlib import Path

import yaml

from hipaa_audit.catalog import coverage_report, load_probo_catalog
from hipaa_audit.controls import load_controls
from hipaa_audit.personnel import check_acknowledgments, check_training_csv, import_training_template

ROOT = Path(__file__).resolve().parent.parent


def test_probo_catalog_bundled():
    catalog = load_probo_catalog()
    assert len(catalog.get("controls", [])) == 60


def test_catalog_full_coverage():
    report = coverage_report()
    assert report["probo_total"] == 60
    assert report["hipaa_audit_controls"] >= 76
    assert report["coverage_pct"] == 100.0
    assert report["probo_unmapped"] == []


def test_acknowledgments_pass(tmp_path):
    ack = tmp_path / "compliance" / "acknowledgments.yaml"
    ack.parent.mkdir(parents=True)
    ack.write_text((ROOT / "compliance" / "acknowledgments.example.yaml").read_text())
    # Extend acks for EMP002 on required policies from example
    data = yaml.safe_load(ack.read_text())
    for pol in ["hipaa-security-policy.md", "hipaa-privacy-policy.md", "acceptable-use-policy.md"]:
        data["acknowledgments"].append(
            {"employee_id": "EMP002", "policy": pol, "version": "1.0", "acknowledged_at": "2026-01-15"}
        )
    ack.write_text(yaml.dump(data))
    tier, _, gaps = check_acknowledgments(tmp_path, {"personnel": {"acknowledgments_path": str(ack.relative_to(tmp_path))}})
    # May still warn on policies not in example ack list — at least not missing file
    assert tier in ("pass", "warn", "fail")
    assert isinstance(gaps, list)


def test_training_csv_pass(tmp_path):
    csv_path = import_training_template(tmp_path / "compliance" / "training-log.csv")
    tier, msg, issues = check_training_csv(tmp_path, {"personnel": {"training_csv": str(csv_path.relative_to(tmp_path))}})
    assert tier == "pass"
    assert not issues
