from pathlib import Path

from hipaa_audit.controls import load_controls


def test_control_catalog_loads():
    controls = load_controls()
    assert len(controls) >= 20
    ids = {c.id for c in controls}
    assert "HIPAA-164.308-a1" in ids
    assert "HIPAA-164.312-e1" in ids


def test_every_control_has_checks():
    for c in load_controls():
        assert c.checks, f"{c.id} has no checks"
