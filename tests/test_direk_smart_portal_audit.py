from plugins.direk_smart_portal.direk_smart_portal_cve_2026_137706_audit import (
    DirekSmartPortalAuditPlugin,
    is_smart_portal_version_vulnerable,
    parse_smart_portal_version,
)


def test_parse_smart_portal_version():
    assert parse_smart_portal_version("2026.11.0") == (2026, 11, 0)
    assert parse_smart_portal_version("2026.12.0") == (2026, 12, 0)
    assert parse_smart_portal_version("") is None


def test_is_smart_portal_version_vulnerable():
    assert is_smart_portal_version_vulnerable((2026, 11, 0))[0] is True
    assert is_smart_portal_version_vulnerable((2026, 12, 0))[0] is False


def test_direk_smart_portal_run_audit():
    res_v = DirekSmartPortalAuditPlugin("portal.local", {"portal_version": "2026.11.0"}).run_audit()
    assert res_v["status"] == "Vulnerable"
    assert "CVE-2026-137706" in res_v["cve"]

    res_ok = DirekSmartPortalAuditPlugin("portal.local", {"portal_version": "2026.12.0"}).run_audit()
    assert res_ok["status"] == "OK"
