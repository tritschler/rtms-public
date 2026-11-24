"""
test_google_chrome_audit.py - Unit tests for Google Chrome / Headless Chromium Version Compliance Audit
(CVE-2026-131088..CVE-2026-130910 and CVE-2026-126885..CVE-2026-126912).
"""

from plugins.google_chrome.google_chrome_cve_2026_126885_audit import (
    GoogleChromeAuditPlugin,
    parse_chrome_version,
    is_chrome_version_vulnerable,
)


def test_plugin_metadata():
    plugin = GoogleChromeAuditPlugin()
    assert plugin.info["cve"] == "CVE-2026-126885"
    assert plugin.info["severity"] == "CRITICAL"
    assert "Chrome" in plugin.info["name"]
    assert plugin.info["version"] == "1.2.0"


def test_version_parsing():
    cdp_json = '{"Browser": "HeadlessChrome/157.0.8103.50", "Protocol-Version": "1.3"}'
    assert parse_chrome_version(cdp_json) == (157, 0, 8103, 50, "157.0.8103.50")

    selenium_json = '{"value": {"nodes": [{"stereotypes": [{"capabilities": {"browserVersion": "158.0.8127.88"}}]}]}}'
    assert parse_chrome_version(selenium_json) == (158, 0, 8127, 88, "158.0.8127.88")
    assert parse_chrome_version("nginx/1.26.0") is None


def test_version_vulnerability_logic():
    vuln_157, reason_157 = is_chrome_version_vulnerable(157, 0, 8103, 50)
    assert vuln_157 is True
    assert "CVE-2026-126885" in reason_157
    assert "CVE-2026-131088" in reason_157
    assert "CVE-2026-134401" in reason_157

    vuln_158_old, reason_158 = is_chrome_version_vulnerable(158, 0, 8127, 10)
    assert vuln_158_old is True
    assert "CVE-2026-131088" in reason_158
    assert "CVE-2026-130910" in reason_158
    assert "CVE-2026-134401" in reason_158

    vuln_158_36, reason_158_36 = is_chrome_version_vulnerable(158, 0, 8127, 36)
    assert vuln_158_36 is True
    assert "CVE-2026-134401" in reason_158_36

    safe, _ = is_chrome_version_vulnerable(158, 0, 8127, 88)
    assert safe is False


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = GoogleChromeAuditPlugin()
    plugin.discovered_ports = [9222]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 9222,
            "service_detected": True,
            "version": "158.0.8127.36",
            "source": "Chrome DevTools Protocol /json/version",
            "is_vulnerable": True,
            "reason": "Affected by CVE-2026-134401",
        },
    )
    res = plugin.run_audit("10.0.0.92", [9222])
    assert res["status"] == "Vulnerable"
    assert "158.0.8127.36" in res["proof"]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 9222,
            "service_detected": True,
            "version": "158.0.8127.88",
            "source": "Chrome DevTools Protocol /json/version",
            "is_vulnerable": False,
            "reason": "Patched >= 158.0.8127.88",
        },
    )
    res_safe = plugin.run_audit("10.0.0.92", [9222])
    assert res_safe["status"] == "OK"
