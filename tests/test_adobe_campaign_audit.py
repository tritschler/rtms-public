from plugins.adobe_campaign.adobe_campaign_cve_2026_125675_audit import (
    AdobeCampaignAuditPlugin,
    is_adobe_campaign_version_vulnerable,
    parse_adobe_campaign_version,
)


def test_parse_adobe_campaign_version():
    assert parse_adobe_campaign_version("Adobe Campaign Classic 7.4.4 build 9403") == (
        7,
        4,
        4,
        9403,
        "7.4.4 build 9403",
    )
    assert parse_adobe_campaign_version("") is None


def test_is_adobe_campaign_version_vulnerable():
    assert is_adobe_campaign_version_vulnerable(7, 4, 4, 9403)[0] is True
    assert is_adobe_campaign_version_vulnerable(7, 4, 4, 9404)[0] is False
    assert is_adobe_campaign_version_vulnerable(7, 4, 5, 9420)[0] is True
    assert is_adobe_campaign_version_vulnerable(7, 4, 5, 9421)[0] is False


def test_adobe_campaign_run_audit(mocker):
    plugin = AdobeCampaignAuditPlugin()
    assert plugin.info["cve"] == "CVE-2026-125675"

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 8080,
            "service_detected": True,
            "version": "7.4.5 build 9420",
            "source": "Adobe Campaign Banner",
            "is_vulnerable": True,
            "reason": "Affected by CVE-2026-125675",
        },
    )
    assert plugin.run_audit("10.0.0.15", [8080])["status"] == "Vulnerable"

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 8080,
            "service_detected": True,
            "version": "7.4.5 build 9421",
            "source": "Adobe Campaign Banner",
            "is_vulnerable": False,
            "reason": "Patched",
        },
    )
    assert plugin.run_audit("10.0.0.15", [8080])["status"] == "OK"
