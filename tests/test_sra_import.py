from pathlib import Path

from hipaa_audit.checks import integrations
from hipaa_audit.sra_import import detect_format, load_sra_json, write_import_artifacts

FIXTURES = Path(__file__).parent / "fixtures"


def test_detect_l0lsec_format():
    data = load_sra_json(FIXTURES / "sra-l0lsec.json")
    assert detect_format(data) == "l0lsec"


def test_detect_saberguard_format():
    data = load_sra_json(FIXTURES / "sra-saberguard.json")
    assert detect_format(data) == "saberguard"


def test_import_writes_markdown_and_summary(tmp_path):
    data = load_sra_json(FIXTURES / "sra-l0lsec.json")
    paths = write_import_artifacts(
        data,
        output_md=tmp_path / "sra-imported.md",
        evidence_dir=tmp_path / "evidence",
    )
    md = paths["markdown"].read_text()
    assert "Example Health Co" in md
    assert "ADM-02" in md
    assert "TEC-05" in md
    assert paths["summary"].exists()


def test_compliancekit_hipaa_fail(tmp_path):
    ck_dir = tmp_path / "evidence" / "compliancekit" / "2026-Q2"
    ck_dir.mkdir(parents=True)
    (ck_dir / "control-mapping.csv").write_text(
        (FIXTURES / "compliancekit-hipaa.csv").read_text()
    )
    evidence = tmp_path / "out"
    evidence.mkdir()
    result = integrations.run(
        {"id": "ck", "title": "CK", "handler": "compliancekit_mapping"},
        repo_path=tmp_path,
        config={"integrations": {"compliancekit": {"enabled": True}}},
        evidence_dir=evidence,
    )
    assert result.status.value == "fail"
