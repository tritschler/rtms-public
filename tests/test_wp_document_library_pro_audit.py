"""
test_wp_document_library_pro_audit.py - Unit tests for WordPress Document Library Pro
Object Injection Audit (CVE-2026-122662).
"""

from plugins.wordpress.wp_document_library_pro.wp_document_library_pro_cve_2026_122662_audit import (
    WPDocumentLibraryProAuditPlugin,
    parse_document_library_pro_version,
    is_document_library_pro_version_vulnerable,
)


def test_plugin_metadata():
    plugin = WPDocumentLibraryProAuditPlugin()
    assert "CVE-2026-122662" in plugin.info["cve"]
    assert plugin.info["severity"] == "CRITICAL"
    assert "Document Library Pro" in plugin.info["name"]


def test_version_parsing():
    html = '<link href="/wp-content/plugins/document-library-pro/assets/css/dlp.css?ver=4.2.1" />'
    assert parse_document_library_pro_version(html) == (4, 2, 1, "4.2.1")
    assert parse_document_library_pro_version("Stable tag: 4.2.2\n") == (4, 2, 2, "4.2.2")
    assert parse_document_library_pro_version("<html>No plugin</html>") is None


def test_version_vulnerability_logic():
    vuln, reason = is_document_library_pro_version_vulnerable(4, 2, 1)
    assert vuln is True
    assert "CVE-2026-122662" in reason

    safe, _ = is_document_library_pro_version_vulnerable(4, 2, 2)
    assert safe is False


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = WPDocumentLibraryProAuditPlugin()
    plugin.discovered_ports = [443]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "plugin_detected": True,
            "version": "4.2.1",
            "source": "Document Library Pro readme.txt",
            "is_vulnerable": True,
            "reason": "Affected < 4.2.2 (<= 4.2.1)",
        },
    )
    res = plugin.run_audit("10.0.0.52", [443])
    assert res["status"] == "Vulnerable"
    assert "CVE-2026-122662" in res["proof"]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "plugin_detected": True,
            "version": "4.2.2",
            "source": "Document Library Pro readme.txt",
            "is_vulnerable": False,
            "reason": "Patched >= 4.2.2",
        },
    )
    res_safe = plugin.run_audit("10.0.0.52", [443])
    assert res_safe["status"] == "OK"
