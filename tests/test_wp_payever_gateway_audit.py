"""
test_wp_payever_gateway_audit.py - Unit tests for WordPress payever WooCommerce Gateway Audit Tool (CVE-2026-93754).
"""

import pytest

from plugins.wordpress.wp_payever_gateway.wp_payever_gateway_cve_2026_93754_audit import (
    WPPayeverGatewayAuditPlugin,
    parse_payever_gateway_version,
    is_payever_gateway_version_vulnerable,
)


def test_plugin_metadata():
    plugin = WPPayeverGatewayAuditPlugin()
    assert plugin.info["cve"] == "CVE-2026-93754"
    assert plugin.info["severity"] == "CRITICAL"
    assert "payever" in plugin.info["name"]
    assert plugin.info["version"] == "1.0.0"


def test_version_parsing():
    html_snippet = (
        '<script src="https://example.com/wp-content/plugins/'
        'payever-woocommerce-gateway/assets/js/payever_payment.js?ver=4.8.0"></script>'
    )
    assert parse_payever_gateway_version(html_snippet) == (4, 8, 0, "4.8.0")
    assert parse_payever_gateway_version("Stable tag: 4.7.9\n") == (4, 7, 9, "4.7.9")
    assert parse_payever_gateway_version("= 4.8.1 =\n* Security fix") == (4, 8, 1, "4.8.1")
    assert parse_payever_gateway_version("<html>WordPress</html>") is None


def test_version_vulnerability_logic():
    vuln, reason = is_payever_gateway_version_vulnerable(4, 8, 0)
    assert vuln is True
    assert "CVE-2026-93754" in reason

    vuln, _ = is_payever_gateway_version_vulnerable(4, 5, 2)
    assert vuln is True

    vuln, reason = is_payever_gateway_version_vulnerable(4, 8, 1)
    assert vuln is False
    assert "patched" in reason


def test_inspect_target_port_vulnerable_readme(mocker):
    plugin = WPPayeverGatewayAuditPlugin()

    def side_effect(target_ip, port, path="/", timeout=4.0):
        if path == "/":
            return {
                "port": port,
                "path": "/",
                "status_code": 200,
                "headers": {},
                "body_snippet": "<html><head><link href='/wp-content/themes/storefront/style.css'></head></html>",
            }
        if path == "/wp-content/plugins/payever-woocommerce-gateway/readme.txt":
            return {
                "port": port,
                "path": path,
                "status_code": 200,
                "headers": {},
                "body_snippet": "=== payever - WooCommerce Gateway ===\nStable tag: 4.8.0\n",
            }
        return None

    mocker.patch.object(plugin, "probe_http_endpoint", side_effect=side_effect)
    hit = plugin.inspect_target_port("192.168.1.24", 443)
    assert hit is not None
    assert hit["plugin_detected"] is True
    assert hit["is_vulnerable"] is True
    assert hit["version"] == "4.8.0"


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = WPPayeverGatewayAuditPlugin()
    plugin.discovered_ports = [443]

    mocker.patch.object(plugin, "inspect_target_port", return_value={
        "port": 443,
        "plugin_detected": True,
        "version": "4.8.0",
        "source": "payever Gateway readme.txt",
        "is_vulnerable": True,
        "reason": "Vulnerable <= 4.8.0",
    })
    res = plugin.run_audit("10.0.0.84", [443])
    assert res["status"] == "Vulnerable"
    assert "CVE-2026-93754" in res["proof"]

    mocker.patch.object(plugin, "inspect_target_port", return_value={
        "port": 443,
        "plugin_detected": True,
        "version": "4.8.1",
        "source": "payever Gateway readme.txt",
        "is_vulnerable": False,
        "reason": "Patched >= 4.8.1",
    })
    res_safe = plugin.run_audit("10.0.0.84", [443])
    assert res_safe["status"] == "OK"
