from plugins.wordpress.wp_memberpress_discord_addon.wp_memberpress_discord_addon_cve_2026_136115_audit import (
    WPMemberPressDiscordAuditPlugin,
    is_memberpress_discord_version_vulnerable,
    parse_memberpress_discord_version,
)


def test_parse_memberpress_discord_version():
    assert parse_memberpress_discord_version("Stable tag: 1.1.5") == (1, 1, 5)
    assert parse_memberpress_discord_version("1.1.6") == (1, 1, 6)
    assert parse_memberpress_discord_version("") is None


def test_is_memberpress_discord_version_vulnerable():
    assert is_memberpress_discord_version_vulnerable((1, 1, 5))[0] is True
    assert is_memberpress_discord_version_vulnerable((1, 1, 6))[0] is False


def test_wp_memberpress_discord_run_audit():
    res_v = WPMemberPressDiscordAuditPlugin("wp.local", {"plugin_version": "1.1.5"}).run_audit()
    assert res_v["status"] == "Vulnerable"
    assert "CVE-2026-136115" in res_v["cve"]

    res_ok = WPMemberPressDiscordAuditPlugin("wp.local", {"plugin_version": "1.1.6"}).run_audit()
    assert res_ok["status"] == "OK"
