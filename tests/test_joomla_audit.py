"""
test_joomla_audit.py - Unit tests for Joomla! CMS Multi-CVE Version Compliance Audit
(CVE-2026-129393, CVE-2026-123214, CVE-2026-126045, CVE-2026-127297).
"""

from plugins.joomla.joomla_cve_2026_129393_audit import (
    JoomlaAuditPlugin,
    parse_joomla_version,
    is_joomla_version_vulnerable,
)


def test_plugin_metadata():
    plugin = JoomlaAuditPlugin()
    assert plugin.info["cve"] == "CVE-2026-129393"
    assert plugin.info["severity"] == "CRITICAL"
    assert "Joomla" in plugin.info["name"]
    assert plugin.info["version"] == "1.0.0"


def test_version_parsing():
    xml_manifest = """<?xml version="1.0" encoding="UTF-8"?>
    <extension version="5.4" type="file" method="upgrade">
        <name>files_joomla</name>
        <version>5.4.10</version>
    </extension>"""
    assert parse_joomla_version(xml_manifest) == (5, 4, 10, "5.4.10")

    html_gen = '<meta name="generator" content="Joomla! - Open Source Content Management - Version 6.2.0" />'
    assert parse_joomla_version(html_gen) == (6, 2, 0, "6.2.0")
    assert parse_joomla_version("nginx/1.26.0") is None


def test_version_vulnerability_logic():
    vuln_5, reason_5 = is_joomla_version_vulnerable(5, 4, 10)
    assert vuln_5 is True
    assert "CVE-2026-129393" in reason_5
    assert "CVE-2026-123214" in reason_5
    assert "CVE-2026-126045" in reason_5
    assert "CVE-2026-127297" in reason_5

    safe_5, _ = is_joomla_version_vulnerable(5, 4, 11)
    assert safe_5 is False

    vuln_6, reason_6 = is_joomla_version_vulnerable(6, 2, 0)
    assert vuln_6 is True
    assert "CVE-2026-129393" in reason_6

    safe_6, _ = is_joomla_version_vulnerable(6, 2, 1)
    assert safe_6 is False

    vuln_3, reason_3 = is_joomla_version_vulnerable(3, 10, 12)
    assert vuln_3 is True
    assert "CVE-2026-126045" in reason_3
    assert "CVE-2026-127297" in reason_3


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = JoomlaAuditPlugin()
    plugin.discovered_ports = [443]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "service_detected": True,
            "version": "5.4.10",
            "source": "Joomla! Core XML manifest (/administrator/manifests/files/joomla.xml)",
            "is_vulnerable": True,
            "reason": "Affected by CVE-2026-129393",
        },
    )
    res = plugin.run_audit("10.0.0.50", [443])
    assert res["status"] == "Vulnerable"
    assert "5.4.10" in res["proof"]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "service_detected": True,
            "version": "5.4.11",
            "source": "Joomla! Core XML manifest (/administrator/manifests/files/joomla.xml)",
            "is_vulnerable": False,
            "reason": "Patched >= 5.4.11",
        },
    )
    res_safe = plugin.run_audit("10.0.0.50", [443])
    assert res_safe["status"] == "OK"
