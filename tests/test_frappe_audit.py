from plugins.frappe.frappe_cve_2026_137550_audit import (
    FrappeAuditPlugin,
    is_frappe_version_vulnerable,
    parse_frappe_version,
)


def test_parse_frappe_version():
    assert parse_frappe_version("15.121.0") == (15, 121, 0)
    assert parse_frappe_version("16.50.0") == (16, 50, 0)
    assert parse_frappe_version("") is None


def test_is_frappe_version_vulnerable():
    assert is_frappe_version_vulnerable((15, 121, 0))[0] is True
    assert is_frappe_version_vulnerable((15, 122, 0))[0] is False
    assert is_frappe_version_vulnerable((16, 49, 0))[0] is True
    assert is_frappe_version_vulnerable((16, 50, 0))[0] is False


def test_frappe_run_audit():
    res_v = FrappeAuditPlugin("frappe.local", {"frappe_version": "15.121.0"}).run_audit()
    assert res_v["status"] == "Vulnerable"
    assert "CVE-2026-137550" in res_v["cve"]

    res_ok = FrappeAuditPlugin("frappe.local", {"frappe_version": "15.122.0"}).run_audit()
    assert res_ok["status"] == "OK"
