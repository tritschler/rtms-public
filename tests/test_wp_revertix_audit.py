from plugins.wordpress.wp_revertix.wp_revertix_cve_2026_134994_audit import (
    WPRevertixAuditPlugin,
    is_revertix_version_vulnerable,
    parse_revertix_version,
)


def test_parse_revertix_version():
    assert parse_revertix_version("Stable tag: 1.0.3") == (1, 0, 3)
    assert parse_revertix_version("1.0.4") == (1, 0, 4)
    assert parse_revertix_version("") is None


def test_is_revertix_version_vulnerable():
    assert is_revertix_version_vulnerable((1, 0, 3))[0] is True
    assert is_revertix_version_vulnerable((1, 0, 4))[0] is False


def test_wp_revertix_run_audit():
    res_v = WPRevertixAuditPlugin("wp.local", {"plugin_version": "1.0.3"}).run_audit()
    assert res_v["status"] == "Vulnerable"
    assert "CVE-2026-134994" in res_v["cve"]

    res_ok = WPRevertixAuditPlugin("wp.local", {"plugin_version": "1.0.4"}).run_audit()
    assert res_ok["status"] == "OK"
