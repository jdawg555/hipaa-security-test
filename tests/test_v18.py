from pathlib import Path

from hipaa_audit.devices import assess_devices, device_csv_template, import_devices_csv
from hipaa_audit.frameworks import soc2_report
from hipaa_audit.questionnaires import assess_questionnaires, send_questionnaire
from hipaa_audit.apps import import_google_apps_csv, merge_discovered

ROOT = Path(__file__).resolve().parent.parent


def test_devices_example_pass(tmp_path):
    register = tmp_path / "compliance" / "devices.yaml"
    register.parent.mkdir(parents=True)
    register.write_text((ROOT / "compliance" / "devices.example.yaml").read_text())
    tier, _, issues = assess_devices(register, {"devices": {"max_last_seen_days": 30}})
    assert tier == "pass"
    assert not issues


def test_devices_import_csv(tmp_path):
    csv_path = device_csv_template(tmp_path / "devices.csv")
    register = tmp_path / "compliance" / "devices.yaml"
    count = import_devices_csv(register, csv_path)
    assert count == 2
    tier, _, _ = assess_devices(register, {"devices": {"max_last_seen_days": 30}})
    assert tier == "pass"


def test_questionnaires_responded_pass(tmp_path):
    q_path = tmp_path / "compliance" / "vendor-questionnaires.yaml"
    q_path.parent.mkdir(parents=True)
    q_path.write_text((ROOT / "compliance" / "vendor-questionnaires.example.yaml").read_text())
    tier, _, issues = assess_questionnaires(q_path, {})
    assert tier == "pass"
    assert not issues


def test_questionnaire_send_flow(tmp_path):
    vendors = tmp_path / "compliance" / "vendors.yaml"
    vendors.parent.mkdir(parents=True)
    vendors.write_text((ROOT / "compliance" / "vendors.example.yaml").read_text())
    q_path = tmp_path / "compliance" / "vendor-questionnaires.yaml"
    entry = send_questionnaire(q_path, vendors, vendor_id="VND-001", contact="v@example.com")
    assert entry is not None
    tier, _, _ = assess_questionnaires(q_path, {})
    assert tier == "warn"


def test_soc2_framework_loads_when_enabled():
    report = soc2_report({"frameworks": {"soc2": True}})
    assert report["soc2_controls"] == 12
    assert report["total_controls"] >= 88


def test_google_csv_import(tmp_path):
    csv_path = tmp_path / "google-apps.csv"
    csv_path.write_text("app_name,users,status\nSlack,42,active\nZoom,10,active\n")
    apps = import_google_apps_csv(csv_path)
    assert len(apps) == 2
    register = tmp_path / "saas-inventory.yaml"
    data = merge_discovered(register, apps, source="google-csv")
    assert len(data["apps"]) == 2
