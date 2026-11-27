from plugins.wordpress.wp_ultimate_member.wp_ultimate_member_cve_2026_134481_audit import (
    WPUltimateMemberAuditPlugin,
    is_ultimate_member_version_vulnerable,
    parse_ultimate_member_version,
)


def test_parse_ultimate_member_version():
    assert parse_ultimate_member_version("Stable tag: 2.14.1") == (2, 14, 1)
    assert parse_ultimate_member_version("2.14.2") == (2, 14, 2)
    assert parse_ultimate_member_version("") is None


def test_is_ultimate_member_version_vulnerable():
    assert is_ultimate_member_version_vulnerable((2, 14, 1))[0] is True
    assert is_ultimate_member_version_vulnerable((2, 14, 2))[0] is False


def test_wp_ultimate_member_run_audit():
    res_v = WPUltimateMemberAuditPlugin("wp.local", {"plugin_version": "2.14.1"}).run_audit()
    assert res_v["status"] == "Vulnerable"
    assert "CVE-2026-134481" in res_v["cve"]

    res_ok = WPUltimateMemberAuditPlugin("wp.local", {"plugin_version": "2.14.2"}).run_audit()
    assert res_ok["status"] == "OK"
