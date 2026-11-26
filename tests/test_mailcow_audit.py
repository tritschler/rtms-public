from plugins.mailcow.mailcow_cve_2026_125757_audit import (
    MailcowAuditPlugin,
    is_mailcow_version_vulnerable,
    parse_mailcow_version,
)


def test_parse_mailcow_version():
    assert parse_mailcow_version("mailcow 2026-10a") == (2026, 10, "2026-10a")
    assert parse_mailcow_version("mailcow 2026-11") == (2026, 11, "2026-11")
    assert parse_mailcow_version("") is None


def test_is_mailcow_version_vulnerable():
    assert is_mailcow_version_vulnerable(2026, 10)[0] is True
    assert is_mailcow_version_vulnerable(2026, 11)[0] is False


def test_mailcow_run_audit(mocker):
    plugin = MailcowAuditPlugin()
    assert plugin.info["cve"] == "CVE-2026-125757"

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "service_detected": True,
            "version": "2026-10",
            "source": "mailcow UI",
            "is_vulnerable": True,
            "reason": "Affected by CVE-2026-125757",
        },
    )
    assert plugin.run_audit("10.0.0.21", [443])["status"] == "Vulnerable"

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "service_detected": True,
            "version": "2026-11",
            "source": "mailcow UI",
            "is_vulnerable": False,
            "reason": "Patched",
        },
    )
    assert plugin.run_audit("10.0.0.21", [443])["status"] == "OK"
