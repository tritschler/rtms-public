"""
test_mozilla_firefox_audit.py - Unit tests for Mozilla Firefox / Firefox ESR & Thunderbird
Version Compliance Audit (CVE-2026-135597..CVE-2026-135501).
"""

from plugins.mozilla_firefox.mozilla_firefox_cve_2026_135597_audit import (
    MozillaFirefoxAuditPlugin,
    parse_firefox_version,
    is_firefox_version_vulnerable,
)


def test_plugin_metadata():
    plugin = MozillaFirefoxAuditPlugin()
    assert plugin.info["cve"] == "CVE-2026-135597"
    assert plugin.info["severity"] == "CRITICAL"
    assert "Firefox" in plugin.info["name"]
    assert plugin.info["version"] == "1.0.0"


def test_version_parsing():
    bidi_json = '{"Browser": "Firefox/160.0.2", "Protocol-Version": "1.0"}'
    assert parse_firefox_version(bidi_json) == (160, 0, 2, "160.0.2")

    selenium_json = '{"value": {"nodes": [{"stereotypes": [{"capabilities": {"browserName": "firefox", "browserVersion": "153.7.0"}}]}]}}'
    assert parse_firefox_version(selenium_json) == (153, 7, 0, "153.7.0")
    assert parse_firefox_version("nginx/1.26.0") is None


def test_version_vulnerability_logic():
    vuln_main, reason_main = is_firefox_version_vulnerable(160, 0, 2)
    assert vuln_main is True
    assert "CVE-2026-135597" in reason_main
    assert "CVE-2026-135501" in reason_main

    safe_main, _ = is_firefox_version_vulnerable(161, 0, 0)
    assert safe_main is False

    vuln_153, reason_153 = is_firefox_version_vulnerable(153, 7, 0)
    assert vuln_153 is True
    assert "CVE-2026-135597" in reason_153
    assert "CVE-2026-135508" in reason_153

    safe_153, _ = is_firefox_version_vulnerable(153, 8, 0)
    assert safe_153 is False

    vuln_115, reason_115 = is_firefox_version_vulnerable(115, 45, 0)
    assert vuln_115 is True
    assert "CVE-2026-135547" in reason_115
    assert "CVE-2026-135508" in reason_115

    safe_115, _ = is_firefox_version_vulnerable(115, 46, 0)
    assert safe_115 is False


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = MozillaFirefoxAuditPlugin()
    plugin.discovered_ports = [4444]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 4444,
            "service_detected": True,
            "version": "160.0.2",
            "source": "WebDriver / GeckoDriver / Selenium Grid /status endpoint",
            "is_vulnerable": True,
            "reason": "Affected by CVE-2026-135597",
        },
    )
    res = plugin.run_audit("10.0.0.93", [4444])
    assert res["status"] == "Vulnerable"
    assert "160.0.2" in res["proof"]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 4444,
            "service_detected": True,
            "version": "161.0.0",
            "source": "WebDriver / GeckoDriver / Selenium Grid /status endpoint",
            "is_vulnerable": False,
            "reason": "Patched >= 161.0.0",
        },
    )
    res_safe = plugin.run_audit("10.0.0.93", [4444])
    assert res_safe["status"] == "OK"
