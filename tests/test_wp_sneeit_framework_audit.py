from plugins.wordpress.wp_sneeit_framework.wp_sneeit_framework_cve_2026_106125_audit import (
    WPSneeitFrameworkAuditPlugin,
    is_sneeit_framework_version_vulnerable,
    parse_sneeit_framework_version,
)


def test_parse_sneeit_framework_version():
    assert parse_sneeit_framework_version("Stable tag: 8.7") == (8, 7, 0)
    assert parse_sneeit_framework_version("8.8.0") == (8, 8, 0)
    assert parse_sneeit_framework_version("") is None


def test_is_sneeit_framework_version_vulnerable():
    assert is_sneeit_framework_version_vulnerable((8, 7, 0))[0] is True
    assert is_sneeit_framework_version_vulnerable((8, 8, 0))[0] is False


def test_wp_sneeit_framework_run_audit():
    res_v = WPSneeitFrameworkAuditPlugin("wp.local", {"plugin_version": "8.7"}).run_audit()
    assert res_v["status"] == "Vulnerable"
    assert "CVE-2026-106125" in res_v["cve"]

    res_ok = WPSneeitFrameworkAuditPlugin("wp.local", {"plugin_version": "8.8"}).run_audit()
    assert res_ok["status"] == "OK"
