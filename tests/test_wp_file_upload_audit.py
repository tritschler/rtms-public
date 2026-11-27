from plugins.wordpress.wp_file_upload.wp_file_upload_cve_2026_134173_audit import (
    WPFileUploadAuditPlugin,
    is_wp_file_upload_version_vulnerable,
    parse_wp_file_upload_version,
)


def test_parse_wp_file_upload_version():
    assert parse_wp_file_upload_version("Stable tag: 5.3.1") == (5, 3, 1)
    assert parse_wp_file_upload_version("5.3.2") == (5, 3, 2)
    assert parse_wp_file_upload_version("") is None


def test_is_wp_file_upload_version_vulnerable():
    assert is_wp_file_upload_version_vulnerable((5, 3, 1))[0] is True
    assert is_wp_file_upload_version_vulnerable((5, 3, 2))[0] is False


def test_wp_file_upload_run_audit():
    res_v = WPFileUploadAuditPlugin("wp.local", {"plugin_version": "5.3.1"}).run_audit()
    assert res_v["status"] == "Vulnerable"
    assert "CVE-2026-134173" in res_v["cve"]

    res_ok = WPFileUploadAuditPlugin("wp.local", {"plugin_version": "5.3.2"}).run_audit()
    assert res_ok["status"] == "OK"
