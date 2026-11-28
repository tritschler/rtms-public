from plugins.wordpress.wp_mastertoolkit.wp_mastertoolkit_cve_2026_134963_audit import (
    WPMasterToolKitAuditPlugin,
    is_mastertoolkit_version_vulnerable,
    parse_mastertoolkit_version,
)


def test_parse_mastertoolkit_version():
    assert parse_mastertoolkit_version("Stable tag: 2.26.1") == (2, 26, 1)
    assert parse_mastertoolkit_version("2.26.2") == (2, 26, 2)
    assert parse_mastertoolkit_version("") is None


def test_is_mastertoolkit_version_vulnerable():
    assert is_mastertoolkit_version_vulnerable((2, 26, 1))[0] is True
    assert is_mastertoolkit_version_vulnerable((2, 26, 2))[0] is False


def test_wp_mastertoolkit_run_audit():
    res_v = WPMasterToolKitAuditPlugin("wp.local", {"plugin_version": "2.26.1"}).run_audit()
    assert res_v["status"] == "Vulnerable"
    assert "CVE-2026-134963" in res_v["cve"]

    res_ok = WPMasterToolKitAuditPlugin("wp.local", {"plugin_version": "2.26.2"}).run_audit()
    assert res_ok["status"] == "OK"
