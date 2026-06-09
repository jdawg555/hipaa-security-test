from pathlib import Path

from hipaa_audit.baas import add_baa, assess_baas, delete_baa, load_baas, update_baa
from hipaa_audit.vendors import add_vendor


def test_baas_lifecycle(tmp_path):
    baas_path = tmp_path / "compliance" / "baas.yaml"
    vendors_path = tmp_path / "compliance" / "vendors.yaml"
    vendor = add_vendor(vendors_path, name="Acme", phi_access="full", baa_executed=False)
    baa = add_baa(
        baas_path,
        vendor_id=vendor["id"],
        vendor_name="Acme",
        effective_date="2026-01-01",
        expiry_date="2027-01-01",
    )
    assert baa["id"] == "BAA-001"
    assert update_baa(baas_path, baa["id"], notes="updated")
    assert delete_baa(baas_path, baa["id"])
    assert not load_baas(baas_path).get("baas")


def test_assess_baas_warns_expiry(tmp_path):
    baas_path = tmp_path / "compliance" / "baas.yaml"
    vendors_path = tmp_path / "compliance" / "vendors.yaml"
    add_vendor(vendors_path, name="Stale", phi_access="full", baa_executed=False)
    add_baa(
        baas_path,
        vendor_id="VND-001",
        vendor_name="Stale",
        effective_date="2024-01-01",
        expiry_date="2020-01-01",
    )
    status, _, issues = assess_baas(baas_path, vendors_path)
    assert status in ("warn", "fail")
    assert issues
