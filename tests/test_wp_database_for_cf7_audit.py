from plugins.wordpress.wp_database_for_cf7.wp_database_for_cf7_cve_2026_115867_audit import (
    WPDatabaseForCF7AuditPlugin,
    is_database_for_cf7_version_vulnerable,
    parse_database_for_cf7_version,
)


def test_parse_database_for_cf7_version():
    assert parse_database_for_cf7_version("Stable tag: 1.5.5") == (1, 5, 5)
    assert parse_database_for_cf7_version("1.5.6") == (1, 5, 6)
    assert parse_database_for_cf7_version("") is None


def test_is_database_for_cf7_version_vulnerable():
    assert is_database_for_cf7_version_vulnerable((1, 5, 5))[0] is True
    assert is_database_for_cf7_version_vulnerable((1, 5, 6))[0] is False


def test_wp_database_for_cf7_run_audit():
    res_v = WPDatabaseForCF7AuditPlugin("wp.local", {"plugin_version": "1.5.5"}).run_audit()
    assert res_v["status"] == "Vulnerable"
    assert "CVE-2026-115867" in res_v["cve"]

    res_ok = WPDatabaseForCF7AuditPlugin("wp.local", {"plugin_version": "1.5.6"}).run_audit()
    assert res_ok["status"] == "OK"
