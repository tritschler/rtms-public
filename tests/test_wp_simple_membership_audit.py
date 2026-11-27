from plugins.wordpress.wp_simple_membership.wp_simple_membership_cve_2026_133951_audit import (
    WPSimpleMembershipAuditPlugin,
    is_simple_membership_version_vulnerable,
    parse_simple_membership_version,
)


def test_parse_simple_membership_version():
    assert parse_simple_membership_version("Stable tag: 4.8.9") == (4, 8, 9)
    assert parse_simple_membership_version("4.8.10") == (4, 8, 10)
    assert parse_simple_membership_version("") is None


def test_is_simple_membership_version_vulnerable():
    assert is_simple_membership_version_vulnerable((4, 8, 9))[0] is True
    assert is_simple_membership_version_vulnerable((4, 8, 10))[0] is False


def test_wp_simple_membership_run_audit():
    res_v = WPSimpleMembershipAuditPlugin("wp.local", {"plugin_version": "4.8.9"}).run_audit()
    assert res_v["status"] == "Vulnerable"
    assert "CVE-2026-133951" in res_v["cve"]

    res_ok = WPSimpleMembershipAuditPlugin("wp.local", {"plugin_version": "4.8.10"}).run_audit()
    assert res_ok["status"] == "OK"
