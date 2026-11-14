"""
test_wp_elex_helpdesk_audit.py - Unit tests for WordPress ELEX HelpDesk PHP Object Injection Audit (CVE-2026-119077, CVE-2026-125855).
"""

from plugins.wordpress.wp_elex_helpdesk.wp_elex_helpdesk_cve_2026_119077_audit import (
    WPElexHelpDeskAuditPlugin,
    parse_elex_helpdesk_version,
    is_elex_helpdesk_version_vulnerable,
)


def test_plugin_metadata():
    plugin = WPElexHelpDeskAuditPlugin()
    assert "CVE-2026-119077" in plugin.info["cve"]
    assert plugin.info["severity"] == "CRITICAL"
    assert "ELEX" in plugin.info["name"]


def test_version_parsing():
    html = '<link href="/wp-content/plugins/elex-helpdesk-customer-support-ticket-system/assets/css/style.css?ver=3.3.9" />'
    assert parse_elex_helpdesk_version(html) == (3, 3, 9, "3.3.9")
    assert parse_elex_helpdesk_version("Stable tag: 3.3.10\n") == (3, 3, 10, "3.3.10")
    assert parse_elex_helpdesk_version("<html>No plugin</html>") is None


def test_version_vulnerability_logic():
    vuln, reason = is_elex_helpdesk_version_vulnerable(3, 3, 9)
    assert vuln is True
    assert "CVE-2026-119077" in reason

    safe, _ = is_elex_helpdesk_version_vulnerable(3, 3, 10)
    assert safe is False


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = WPElexHelpDeskAuditPlugin()
    plugin.discovered_ports = [443]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "plugin_detected": True,
            "version": "3.3.9",
            "source": "ELEX WordPress HelpDesk & Customer Ticketing System readme.txt",
            "is_vulnerable": True,
            "reason": "Affected <= 3.3.9 (< 3.3.10)",
        },
    )
    res = plugin.run_audit("10.0.0.50", [443])
    assert res["status"] == "Vulnerable"
    assert "CVE-2026-119077" in res["proof"]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "plugin_detected": True,
            "version": "3.3.10",
            "source": "ELEX WordPress HelpDesk & Customer Ticketing System readme.txt",
            "is_vulnerable": False,
            "reason": "Patched >= 3.3.10",
        },
    )
    res_safe = plugin.run_audit("10.0.0.50", [443])
    assert res_safe["status"] == "OK"
