"""
test_wp_printcart_designer_audit.py - Unit tests for WordPress Printcart Product Designer Audit Tool (CVE-2026-19803).
"""

import pytest

from plugins.wordpress.wp_printcart_designer.wp_printcart_designer_cve_2026_19803_audit import (
    WPPrintcartDesignerAuditPlugin,
    parse_printcart_designer_version,
    is_printcart_designer_version_vulnerable,
)


def test_plugin_metadata():
    plugin = WPPrintcartDesignerAuditPlugin()
    assert plugin.info["cve"] == "CVE-2026-19803"
    assert plugin.info["severity"] == "CRITICAL"
    assert "Printcart" in plugin.info["name"]
    assert plugin.info["version"] == "1.0.0"


def test_version_parsing():
    html_snippet = (
        '<link rel="stylesheet" href="https://example.com/wp-content/plugins/'
        'web-to-print-online-designer/assets/css/nbdesigner.css?ver=2.13.2" />'
    )
    assert parse_printcart_designer_version(html_snippet) == (2, 13, 2, "2.13.2")
    assert parse_printcart_designer_version("Stable tag: 2.13.1\n") == (2, 13, 1, "2.13.1")
    assert parse_printcart_designer_version("= 2.13.3 =\n* Security fix") == (2, 13, 3, "2.13.3")
    assert parse_printcart_designer_version("<html>WordPress</html>") is None


def test_version_vulnerability_logic():
    vuln, reason = is_printcart_designer_version_vulnerable(2, 13, 2)
    assert vuln is True
    assert "CVE-2026-19803" in reason

    vuln, _ = is_printcart_designer_version_vulnerable(2, 10, 0)
    assert vuln is True

    vuln, reason = is_printcart_designer_version_vulnerable(2, 13, 3)
    assert vuln is False
    assert "patched" in reason


def test_inspect_target_port_vulnerable_readme(mocker):
    plugin = WPPrintcartDesignerAuditPlugin()

    def side_effect(target_ip, port, path="/", timeout=4.0):
        if path == "/":
            return {
                "port": port,
                "path": "/",
                "status_code": 200,
                "headers": {},
                "body_snippet": "<html><head><link href='/wp-content/themes/storefront/style.css'></head></html>",
            }
        if path == "/wp-content/plugins/web-to-print-online-designer/readme.txt":
            return {
                "port": port,
                "path": path,
                "status_code": 200,
                "headers": {},
                "body_snippet": "=== Printcart Store – Web to Print Product Designer for WooCommerce ===\nStable tag: 2.13.2\n",
            }
        return None

    mocker.patch.object(plugin, "probe_http_endpoint", side_effect=side_effect)
    hit = plugin.inspect_target_port("192.168.1.23", 443)
    assert hit is not None
    assert hit["plugin_detected"] is True
    assert hit["is_vulnerable"] is True
    assert hit["version"] == "2.13.2"


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = WPPrintcartDesignerAuditPlugin()
    plugin.discovered_ports = [443]

    mocker.patch.object(plugin, "inspect_target_port", return_value={
        "port": 443,
        "plugin_detected": True,
        "version": "2.13.2",
        "source": "Printcart Designer readme.txt",
        "is_vulnerable": True,
        "reason": "Vulnerable <= 2.13.2",
    })
    res = plugin.run_audit("10.0.0.83", [443])
    assert res["status"] == "Vulnerable"
    assert "CVE-2026-19803" in res["proof"]

    mocker.patch.object(plugin, "inspect_target_port", return_value={
        "port": 443,
        "plugin_detected": True,
        "version": "2.13.3",
        "source": "Printcart Designer readme.txt",
        "is_vulnerable": False,
        "reason": "Patched >= 2.13.3",
    })
    res_safe = plugin.run_audit("10.0.0.83", [443])
    assert res_safe["status"] == "OK"
