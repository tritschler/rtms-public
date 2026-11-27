from plugins.laradashboard.laradashboard_cve_2026_137544_audit import (
    LaraDashboardAuditPlugin,
    is_laradashboard_version_vulnerable,
    parse_laradashboard_version,
)


def test_parse_laradashboard_version():
    assert parse_laradashboard_version("1.4.2") == (1, 4, 2)
    assert parse_laradashboard_version("1.5.0") == (1, 5, 0)
    assert parse_laradashboard_version("") is None


def test_is_laradashboard_version_vulnerable():
    assert is_laradashboard_version_vulnerable((1, 4, 2))[0] is True
    assert is_laradashboard_version_vulnerable((1, 5, 0))[0] is False


def test_laradashboard_run_audit():
    res_v = LaraDashboardAuditPlugin("lara.local", {"laradashboard_version": "1.4.2"}).run_audit()
    assert res_v["status"] == "Vulnerable"
    assert "CVE-2026-137544" in res_v["cve"]

    res_ok = LaraDashboardAuditPlugin("lara.local", {"laradashboard_version": "1.5.0"}).run_audit()
    assert res_ok["status"] == "OK"
