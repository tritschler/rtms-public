from plugins.wordpress.wp_job_portal.wp_job_portal_cve_2026_135641_audit import (
    WPJobPortalAuditPlugin,
    is_wp_job_portal_version_vulnerable,
    parse_wp_job_portal_version,
)


def test_parse_wp_job_portal_version():
    assert parse_wp_job_portal_version("Stable tag: 2.7.2") == (2, 7, 2)
    assert parse_wp_job_portal_version("2.7.3") == (2, 7, 3)
    assert parse_wp_job_portal_version("") is None


def test_is_wp_job_portal_version_vulnerable():
    assert is_wp_job_portal_version_vulnerable((2, 7, 2))[0] is True
    assert is_wp_job_portal_version_vulnerable((2, 7, 3))[0] is False


def test_wp_job_portal_run_audit():
    res_v = WPJobPortalAuditPlugin("wp.local", {"plugin_version": "2.7.2"}).run_audit()
    assert res_v["status"] == "Vulnerable"
    assert "CVE-2026-135641" in res_v["cve"]

    res_ok = WPJobPortalAuditPlugin("wp.local", {"plugin_version": "2.7.3"}).run_audit()
    assert res_ok["status"] == "OK"
