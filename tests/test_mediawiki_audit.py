"""
test_mediawiki_audit.py - Unit tests for MediaWiki & Extensions Multi-CVE Version Compliance Audit
(CVE-2026-132726, CVE-2026-132694, CVE-2026-132697, CVE-2026-132669).
"""

from plugins.mediawiki.mediawiki_cve_2026_132726_audit import (
    MediaWikiAuditPlugin,
    parse_mediawiki_version,
    is_mediawiki_version_vulnerable,
)


def test_plugin_metadata():
    plugin = MediaWikiAuditPlugin()
    assert plugin.info["cve"] == "CVE-2026-132726"
    assert plugin.info["severity"] == "CRITICAL"
    assert "MediaWiki" in plugin.info["name"]
    assert plugin.info["version"] == "1.0.0"


def test_version_parsing():
    siteinfo_json = '{"query":{"general":{"generator":"MediaWiki 1.46.2"}}}'
    assert parse_mediawiki_version(siteinfo_json) == (1, 46, 2, "1.46.2")

    html_gen = '<meta name="generator" content="MediaWiki 1.43.11"/>'
    assert parse_mediawiki_version(html_gen) == (1, 43, 11, "1.43.11")
    assert parse_mediawiki_version("nginx/1.26.0") is None


def test_version_vulnerability_logic():
    vuln_143, reason_143 = is_mediawiki_version_vulnerable(1, 43, 11)
    assert vuln_143 is True
    assert "CVE-2026-132726" in reason_143
    assert "CVE-2026-132697" in reason_143
    assert "CVE-2026-132669" in reason_143

    safe_143, _ = is_mediawiki_version_vulnerable(1, 43, 12)
    assert safe_143 is False

    vuln_145, reason_145 = is_mediawiki_version_vulnerable(1, 45, 6)
    assert vuln_145 is True
    assert "CVE-2026-132726" in reason_145

    safe_145, _ = is_mediawiki_version_vulnerable(1, 45, 7)
    assert safe_145 is False

    vuln_146, reason_146 = is_mediawiki_version_vulnerable(1, 46, 2)
    assert vuln_146 is True
    assert "CVE-2026-132694" in reason_146
    assert "CVE-2026-132726" in reason_146

    safe_146, _ = is_mediawiki_version_vulnerable(1, 46, 3)
    assert safe_146 is False

    vuln_147, reason_147 = is_mediawiki_version_vulnerable(1, 47, 0)
    assert vuln_147 is True
    assert "CVE-2026-132726" in reason_147

    safe_147, _ = is_mediawiki_version_vulnerable(1, 47, 1)
    assert safe_147 is False


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = MediaWikiAuditPlugin()
    plugin.discovered_ports = [443]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "service_detected": True,
            "version": "1.46.2",
            "source": "MediaWiki siteinfo API (/api.php)",
            "is_vulnerable": True,
            "reason": "Affected by CVE-2026-132726",
        },
    )
    res = plugin.run_audit("10.0.0.55", [443])
    assert res["status"] == "Vulnerable"
    assert "1.46.2" in res["proof"]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "service_detected": True,
            "version": "1.46.3",
            "source": "MediaWiki siteinfo API (/api.php)",
            "is_vulnerable": False,
            "reason": "Patched >= 1.46.3",
        },
    )
    res_safe = plugin.run_audit("10.0.0.55", [443])
    assert res_safe["status"] == "OK"
