from plugins.wordpress.wp_amelia.wp_amelia_cve_2026_135930_audit import (
    WPAmeliaAuditPlugin,
    is_amelia_version_vulnerable,
    parse_amelia_version,
)


def test_parse_amelia_version():
    assert parse_amelia_version("Stable tag: 2.4.14") == (2, 4, 14)
    assert parse_amelia_version("2.4.15") == (2, 4, 15)
    assert parse_amelia_version("") is None


def test_is_amelia_version_vulnerable():
    assert is_amelia_version_vulnerable((2, 4, 14))[0] is True
    assert is_amelia_version_vulnerable((2, 4, 15))[0] is False


def test_wp_amelia_run_audit():
    res_v = WPAmeliaAuditPlugin("wp.local", {"plugin_version": "2.4.14"}).run_audit()
    assert res_v["status"] == "Vulnerable"
    assert "CVE-2026-135930" in res_v["cve"]

    res_ok = WPAmeliaAuditPlugin("wp.local", {"plugin_version": "2.4.15"}).run_audit()
    assert res_ok["status"] == "OK"
