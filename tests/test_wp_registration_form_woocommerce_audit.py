"""
test_wp_registration_form_woocommerce_audit.py - Unit tests for WordPress Registration Form for WooCommerce Audit Tool (CVE-2026-119075).
"""

import pytest

from plugins.wordpress.wp_registration_form_woocommerce.wp_registration_form_woocommerce_cve_2026_119075_audit import (
    WPRegistrationFormWooCommerceAuditPlugin,
    parse_registration_form_wc_version,
    is_registration_form_wc_version_vulnerable,
)


def test_plugin_metadata():
    plugin = WPRegistrationFormWooCommerceAuditPlugin()
    assert plugin.info["cve"] == "CVE-2026-119075"
    assert plugin.info["severity"] == "CRITICAL"
    assert "Registration Form for WooCommerce" in plugin.info["name"]
    assert plugin.info["version"] == "1.0.0"


def test_version_parsing():
    html_snippet = (
        '<link rel="stylesheet" href="https://example.com/wp-content/plugins/'
        'registration-form-for-woocommerce/assets/css/frontend.css?ver=1.1.4" />'
    )
    assert parse_registration_form_wc_version(html_snippet) == (1, 1, 4, "1.1.4")
    assert parse_registration_form_wc_version("Stable tag: 1.1.3\n") == (1, 1, 3, "1.1.3")
    assert parse_registration_form_wc_version("= 1.1.5 - 2026-11-06 =") == (1, 1, 5, "1.1.5")
    assert parse_registration_form_wc_version("<html>WordPress</html>") is None


def test_version_vulnerability_logic():
    vuln, reason = is_registration_form_wc_version_vulnerable(1, 1, 4)
    assert vuln is True
    assert "CVE-2026-119075" in reason

    vuln, _ = is_registration_form_wc_version_vulnerable(1, 0, 2)
    assert vuln is True

    vuln, reason = is_registration_form_wc_version_vulnerable(1, 1, 5)
    assert vuln is False
    assert "patched" in reason


def test_inspect_target_port_vulnerable_readme(mocker):
    plugin = WPRegistrationFormWooCommerceAuditPlugin()

    def side_effect(target_ip, port, path="/", timeout=4.0):
        if path == "/":
            return {
                "port": port,
                "path": "/",
                "status_code": 200,
                "headers": {},
                "body_snippet": "<html><head><link href='/wp-content/themes/storefront/style.css'></head></html>",
            }
        if path == "/wp-content/plugins/registration-form-for-woocommerce/readme.txt":
            return {
                "port": port,
                "path": path,
                "status_code": 200,
                "headers": {},
                "body_snippet": "=== Registration Form for WooCommerce ===\nContributors: ThemeGrill\nStable tag: 1.1.4\n",
            }
        return None

    mocker.patch.object(plugin, "probe_http_endpoint", side_effect=side_effect)
    hit = plugin.inspect_target_port("192.168.1.21", 443)
    assert hit is not None
    assert hit["plugin_detected"] is True
    assert hit["is_vulnerable"] is True
    assert hit["version"] == "1.1.4"


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = WPRegistrationFormWooCommerceAuditPlugin()
    plugin.discovered_ports = [443]

    mocker.patch.object(plugin, "inspect_target_port", return_value={
        "port": 443,
        "plugin_detected": True,
        "version": "1.1.4",
        "source": "Plugin readme.txt",
        "is_vulnerable": True,
        "reason": "Vulnerable <= 1.1.4",
    })
    res = plugin.run_audit("10.0.0.81", [443])
    assert res["status"] == "Vulnerable"
    assert "CVE-2026-119075" in res["proof"]

    mocker.patch.object(plugin, "inspect_target_port", return_value={
        "port": 443,
        "plugin_detected": True,
        "version": "1.1.5",
        "source": "Plugin readme.txt",
        "is_vulnerable": False,
        "reason": "Patched >= 1.1.5",
    })
    res_safe = plugin.run_audit("10.0.0.81", [443])
    assert res_safe["status"] == "OK"
