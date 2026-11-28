from plugins.wordpress.wp_webinar_ignition.wp_webinar_ignition_cve_2026_135933_audit import (
    WPWebinarIgnitionAuditPlugin,
    is_webinar_ignition_version_vulnerable,
    parse_webinar_ignition_version,
)


def test_parse_webinar_ignition_version():
    assert parse_webinar_ignition_version("Stable tag: 4.28.1") == (4, 28, 1)
    assert parse_webinar_ignition_version("4.28.2") == (4, 28, 2)
    assert parse_webinar_ignition_version("") is None


def test_is_webinar_ignition_version_vulnerable():
    assert is_webinar_ignition_version_vulnerable((4, 28, 1))[0] is True
    assert is_webinar_ignition_version_vulnerable((4, 28, 2))[0] is False


def test_wp_webinar_ignition_run_audit():
    res_v = WPWebinarIgnitionAuditPlugin("wp.local", {"plugin_version": "4.28.1"}).run_audit()
    assert res_v["status"] == "Vulnerable"
    assert "CVE-2026-135933" in res_v["cve"]

    res_ok = WPWebinarIgnitionAuditPlugin("wp.local", {"plugin_version": "4.28.2"}).run_audit()
    assert res_ok["status"] == "OK"
