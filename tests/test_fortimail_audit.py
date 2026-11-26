from plugins.fortimail.fortimail_cve_2026_126263_audit import (
    FortiMailAuditPlugin,
    is_fortimail_version_vulnerable,
    parse_fortimail_version,
)


def test_parse_fortimail_version():
    assert parse_fortimail_version("FortiMail v7.6.4") == (7, 6, 4, "7.6.4")
    assert parse_fortimail_version("FortiMail 8.0.1") == (8, 0, 1, "8.0.1")
    assert parse_fortimail_version("invalid") is None


def test_is_fortimail_version_vulnerable():
    assert is_fortimail_version_vulnerable(7, 4, 6)[0] is True
    assert is_fortimail_version_vulnerable(7, 6, 4)[0] is True
    assert is_fortimail_version_vulnerable(8, 0, 1)[0] is True
    assert is_fortimail_version_vulnerable(8, 0, 2)[0] is False


def test_fortimail_run_audit(mocker):
    plugin = FortiMailAuditPlugin()
    assert plugin.info["cve"] == "CVE-2026-126263"

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "service_detected": True,
            "version": "7.6.4",
            "source": "FortiMail WebUI",
            "is_vulnerable": True,
            "reason": "Affected by CVE-2026-126263",
        },
    )
    assert plugin.run_audit("10.0.0.17", [443])["status"] == "Vulnerable"

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "service_detected": True,
            "version": "7.6.5",
            "source": "FortiMail WebUI",
            "is_vulnerable": False,
            "reason": "Patched",
        },
    )
    assert plugin.run_audit("10.0.0.17", [443])["status"] == "OK"
