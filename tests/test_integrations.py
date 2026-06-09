import json
from pathlib import Path

from hipaa_audit.checks import integrations


def _check(handler: str, check_id: str = "TEST") -> dict:
    return {"id": check_id, "title": "Test", "handler": handler}


def test_parse_prowler_failures():
    data = [{"status": "FAIL", "check_title": "S3 bucket public"}]
    assert integrations._parse_prowler_json(data, "p.json") == ["S3 bucket public"]


def test_prowler_clean(tmp_path):
    prowler_dir = tmp_path / "evidence" / "prowler"
    prowler_dir.mkdir(parents=True)
    (prowler_dir / "report.json").write_text(json.dumps([{"status": "PASS", "check_title": "ok"}]))
    evidence = tmp_path / "out"
    evidence.mkdir()
    result = integrations.run(
        _check("prowler_findings"),
        repo_path=tmp_path,
        config={"integrations": {"prowler": {"enabled": True}}},
        evidence_dir=evidence,
    )
    assert result.status.value == "pass"


def test_trivy_critical_fails(tmp_path):
    trivy_dir = tmp_path / "evidence" / "trivy"
    trivy_dir.mkdir(parents=True)
    payload = {"Results": [{"Vulnerabilities": [{"VulnerabilityID": "CVE-1", "Severity": "CRITICAL"}]}]}
    (trivy_dir / "report.json").write_text(json.dumps(payload))
    evidence = tmp_path / "out"
    evidence.mkdir()
    result = integrations.run(
        _check("trivy_vulnerabilities"),
        repo_path=tmp_path,
        config={"integrations": {"trivy": {"enabled": True}}},
        evidence_dir=evidence,
    )
    assert result.status.value == "fail"


def test_ai_register_skip_by_default(tmp_path):
    evidence = tmp_path / "out"
    evidence.mkdir()
    result = integrations.run(
        _check("ai_risk_register", "HIPAA-AI-001"),
        repo_path=tmp_path,
        config={"integrations": {}},
        evidence_dir=evidence,
    )
    assert result.status.value == "skip"
