from plugins.wordpress.wp_media_library_assistant.wp_media_library_assistant_cve_2026_135009_audit import (
    WPMediaLibraryAssistantAuditPlugin,
    is_mla_version_vulnerable,
    parse_mla_version,
)


def test_parse_mla_version():
    assert parse_mla_version("Stable tag: 3.43") == (3, 43, 0)
    assert parse_mla_version("3.44") == (3, 44, 0)
    assert parse_mla_version("") is None


def test_is_mla_version_vulnerable():
    assert is_mla_version_vulnerable((3, 43, 0))[0] is True
    assert is_mla_version_vulnerable((3, 44, 0))[0] is False


def test_wp_media_library_assistant_run_audit():
    res_v = WPMediaLibraryAssistantAuditPlugin("wp.local", {"plugin_version": "3.43"}).run_audit()
    assert res_v["status"] == "Vulnerable"
    assert "CVE-2026-135009" in res_v["cve"]

    res_ok = WPMediaLibraryAssistantAuditPlugin("wp.local", {"plugin_version": "3.44"}).run_audit()
    assert res_ok["status"] == "OK"
