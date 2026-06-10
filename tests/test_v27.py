import json
from pathlib import Path

from hipaa_audit.controls import load_controls
from hipaa_audit.frameworks import hitrust_report, pci_report
from hipaa_audit.prowler_crosswalk import load_crosswalk, rollup_requirements


def test_hitrust_supplement_loads():
    cfg = {"frameworks": {"hitrust": True}}
    controls = load_controls(config=cfg)
    hitrust = [c for c in controls if c.id.startswith("HITRUST-")]
    assert len(hitrust) >= 5


def test_pci_supplement_loads():
    cfg = {"frameworks": {"pci": True}}
    controls = load_controls(config=cfg)
    pci = [c for c in controls if c.id.startswith("PCI-")]
    assert len(pci) >= 5


def test_framework_reports():
    cfg = {"frameworks": {"hitrust": True, "pci": True}}
    assert hitrust_report(cfg)["hitrust_controls"] >= 5
    assert pci_report(cfg)["pci_controls"] >= 5


def test_azure_crosswalk_rollup(tmp_path):
    prowler_dir = tmp_path / "evidence" / "prowler-azure"
    prowler_dir.mkdir(parents=True)
    payload = [{"status": "FAIL", "check_id": "defender_ensure_defender_for_server_is_on"}]
    (prowler_dir / "r.json").write_text(json.dumps(payload))
    crosswalk = load_crosswalk(provider="azure")
    assert len(crosswalk.get("requirements", [])) >= 20
    from hipaa_audit.prowler_crosswalk import collect_finding_statuses

    statuses = collect_finding_statuses([prowler_dir / "r.json"])
    rollup = rollup_requirements(statuses, provider="azure")
    assert any(r["status"] == "fail" for r in rollup)


def test_gitlab_adapter_missing_token():
    from hipaa_audit.platform.adapters.gitlab import GitLabAdapter

    result = GitLabAdapter().test_connection({"gitlab": {"enabled": True, "project": "g/p"}})
    assert not result.ok
    assert "GITLAB_TOKEN" in result.message


def test_gitlab_checks_skip_when_disabled(tmp_path):
    from hipaa_audit.checks.gitlab import run
    from hipaa_audit.models import CheckStatus

    result = run(
        {"id": "x", "handler": "branch_protection"},
        repo_path=tmp_path,
        config={"gitlab": {"enabled": False}},
        evidence_dir=tmp_path,
    )
    assert result.status == CheckStatus.SKIP
