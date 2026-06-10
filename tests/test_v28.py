import json
from pathlib import Path

from hipaa_audit.ai_assist import suggest_sig_lite_responses
from hipaa_audit.checks import integrations
from hipaa_audit.platform.adapters.snyk import SnykAdapter
from hipaa_audit.platform.parity import load_connector_catalog


def _check(handler: str) -> dict:
    return {"id": "TEST", "title": "Test", "handler": handler}


def test_ai_assist_keywords():
    text = "We maintain SOC 2 Type II and enforce MFA for all admin access."
    result = suggest_sig_lite_responses(text, {"ai_assist": {"enabled": True}})
    assert "error" not in result
    assert result["suggestions"]["soc2_or_iso"]["suggested"] is True
    assert result["suggestions"]["mfa_enforced"]["suggested"] is True


def test_ai_assist_phi_guard():
    result = suggest_sig_lite_responses(
        "Patient MRN 123-45-6789",
        {"ai_assist": {"enabled": True}},
    )
    assert "PHI" in result["error"]


def test_ai_assist_disabled():
    result = suggest_sig_lite_responses("SOC 2 certified", {"ai_assist": {"enabled": False}})
    assert "disabled" in result["error"].lower()


def test_snyk_critical_fails(tmp_path):
    snyk_dir = tmp_path / "evidence" / "snyk"
    snyk_dir.mkdir(parents=True)
    payload = {"vulnerabilities": [{"title": "XSS", "severity": "high"}]}
    (snyk_dir / "report.json").write_text(json.dumps(payload))
    evidence = tmp_path / "out"
    evidence.mkdir()
    result = integrations.run(
        _check("snyk_vulnerabilities"),
        repo_path=tmp_path,
        config={"integrations": {"snyk": {"enabled": True}}},
        evidence_dir=evidence,
    )
    assert result.status.value == "fail"


def test_snyk_adapter_disabled():
    result = SnykAdapter().test_connection({"integrations": {"snyk": {"enabled": False}}})
    assert not result.ok


def test_snyk_adapter_missing_token():
    result = SnykAdapter().test_connection({"integrations": {"snyk": {"enabled": True}}})
    assert not result.ok
    assert "SNYK_TOKEN" in result.message


def test_connector_catalog_loads():
    catalog = load_connector_catalog()
    ids = {c["id"] for c in catalog.get("connectors", [])}
    assert "snyk" in ids
    assert "bamboohr" in ids
    assert len(ids) >= 15


def test_checkov_pr_workflow_exists():
    wf = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "checkov-pr.yml"
    assert wf.exists()
    assert "checkov" in wf.read_text().lower()
