"""
test_phpmyfaq_audit.py - Unit tests for phpMyFAQ Version Compliance Audit
(CVE-2026-130369 / CVE-2026-130371).
"""

from plugins.phpmyfaq.phpmyfaq_cve_2026_130369_audit import (
    PhpMyFAQAuditPlugin,
    parse_phpmyfaq_version,
    is_phpmyfaq_version_vulnerable,
)


def test_plugin_metadata():
    plugin = PhpMyFAQAuditPlugin()
    assert "CVE-2026-130369" in plugin.info["cve"]
    assert plugin.info["severity"] == "CRITICAL"
    assert "phpMyFAQ" in plugin.info["name"]
    assert plugin.info["version"] == "1.0.0"


def test_version_parsing():
    assert parse_phpmyfaq_version('<meta name="generator" content="phpMyFAQ 4.1.10">') == (4, 1, 10, "", "4.1.10")
    assert parse_phpmyfaq_version("phpMyFAQ 4.2.0-RC.1") == (4, 2, 0, "RC.1", "4.2.0-RC.1")
    assert parse_phpmyfaq_version('{"version": "4.1.12"}') == (4, 1, 12, "", "4.1.12")
    assert parse_phpmyfaq_version("Apache/2.4.58") is None


def test_version_vulnerability_logic():
    vuln_4110, reason_4110 = is_phpmyfaq_version_vulnerable(4, 1, 10)
    assert vuln_4110 is True
    assert "CVE-2026-130369" in reason_4110

    vuln_405, reason_405 = is_phpmyfaq_version_vulnerable(4, 0, 5)
    assert vuln_405 is True
    assert "CVE-2026-130371" in reason_405

    vuln_rc1, _ = is_phpmyfaq_version_vulnerable(4, 2, 0, "RC.1", "4.2.0-RC.1")
    assert vuln_rc1 is True

    safe_4112, _ = is_phpmyfaq_version_vulnerable(4, 1, 12)
    assert safe_4112 is False

    safe_rc2, _ = is_phpmyfaq_version_vulnerable(4, 2, 0, "RC.2", "4.2.0-RC.2")
    assert safe_rc2 is False


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = PhpMyFAQAuditPlugin()
    plugin.discovered_ports = [443]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "service_detected": True,
            "version": "4.1.11",
            "source": "HTTP Root Page (/)",
            "is_vulnerable": True,
            "reason": "Affected by CVE-2026-130369 and CVE-2026-130371 (< 4.1.12)",
        },
    )
    res = plugin.run_audit("10.0.0.87", [443])
    assert res["status"] == "Vulnerable"
    assert "CVE-2026-130369" in res["proof"]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "service_detected": True,
            "version": "4.1.12",
            "source": "HTTP Root Page (/)",
            "is_vulnerable": False,
            "reason": "Patched >= 4.1.12",
        },
    )
    res_safe = plugin.run_audit("10.0.0.87", [443])
    assert res_safe["status"] == "OK"
