"""
test_wp_simple_shopping_cart_audit.py - Unit tests for WordPress Simple Shopping Cart
Object Injection Audit (CVE-2026-131782).
"""

from plugins.wordpress.wp_simple_shopping_cart.wp_simple_shopping_cart_cve_2026_131782_audit import (
    WPSimpleShoppingCartAuditPlugin,
    parse_wp_simple_shopping_cart_version,
    is_wp_simple_shopping_cart_version_vulnerable,
)


def test_plugin_metadata():
    plugin = WPSimpleShoppingCartAuditPlugin()
    assert "CVE-2026-131782" in plugin.info["cve"]
    assert plugin.info["severity"] == "CRITICAL"
    assert "Simple Shopping Cart" in plugin.info["name"]


def test_version_parsing():
    html = '<link rel="stylesheet" href="/wp-content/plugins/wordpress-simple-paypal-shopping-cart/wp_shopping_cart_style.css?ver=5.3.3">'
    assert parse_wp_simple_shopping_cart_version(html) == (5, 3, 3, "5.3.3")
    assert parse_wp_simple_shopping_cart_version("Stable tag: 5.3.4\n") == (5, 3, 4, "5.3.4")
    assert parse_wp_simple_shopping_cart_version("<html>No plugin</html>") is None


def test_version_vulnerability_logic():
    vuln, reason = is_wp_simple_shopping_cart_version_vulnerable(5, 3, 3)
    assert vuln is True
    assert "CVE-2026-131782" in reason

    safe, _ = is_wp_simple_shopping_cart_version_vulnerable(5, 3, 4)
    assert safe is False


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = WPSimpleShoppingCartAuditPlugin()
    plugin.discovered_ports = [443]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "plugin_detected": True,
            "version": "5.3.3",
            "source": "Simple Shopping Cart readme.txt (/wp-content/plugins/wordpress-simple-paypal-shopping-cart/readme.txt)",
            "is_vulnerable": True,
            "reason": "Affected <= 5.3.3 (< 5.3.4)",
        },
    )
    res = plugin.run_audit("10.0.0.55", [443])
    assert res["status"] == "Vulnerable"
    assert "CVE-2026-131782" in res["proof"]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "plugin_detected": True,
            "version": "5.3.4",
            "source": "Simple Shopping Cart readme.txt (/wp-content/plugins/wordpress-simple-paypal-shopping-cart/readme.txt)",
            "is_vulnerable": False,
            "reason": "Patched >= 5.3.4",
        },
    )
    res_safe = plugin.run_audit("10.0.0.55", [443])
    assert res_safe["status"] == "OK"
