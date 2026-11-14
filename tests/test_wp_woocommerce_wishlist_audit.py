"""
test_wp_woocommerce_wishlist_audit.py - Unit tests for WordPress Woocommerce Wishlist Missing Authorization & CSRF Audit (CVE-2026-124763).
"""

from plugins.wordpress.wp_woocommerce_wishlist.wp_woocommerce_wishlist_cve_2026_124763_audit import (
    WPWooCommerceWishlistAuditPlugin,
    parse_woocommerce_wishlist_version,
    is_woocommerce_wishlist_version_vulnerable,
)


def test_plugin_metadata():
    plugin = WPWooCommerceWishlistAuditPlugin()
    assert "CVE-2026-124763" in plugin.info["cve"]
    assert plugin.info["severity"] == "CRITICAL"
    assert "Woocommerce" in plugin.info["name"]


def test_version_parsing():
    html = '<link href="/wp-content/plugins/woocommerce-wishlist/assets/css/style.css?ver=1.1.0" />'
    assert parse_woocommerce_wishlist_version(html) == (1, 1, 0, "1.1.0")
    assert parse_woocommerce_wishlist_version("Stable tag: 1.1.1\n") == (1, 1, 1, "1.1.1")
    assert parse_woocommerce_wishlist_version("<html>No plugin</html>") is None


def test_version_vulnerability_logic():
    vuln, reason = is_woocommerce_wishlist_version_vulnerable(1, 1, 0)
    assert vuln is True
    assert "CVE-2026-124763" in reason

    safe, _ = is_woocommerce_wishlist_version_vulnerable(1, 1, 1)
    assert safe is False


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = WPWooCommerceWishlistAuditPlugin()
    plugin.discovered_ports = [443]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "plugin_detected": True,
            "version": "1.1.0",
            "source": "Woocommerce Wishlist readme.txt",
            "is_vulnerable": True,
            "reason": "Affected <= 1.1.0 (< 1.1.1)",
        },
    )
    res = plugin.run_audit("10.0.0.50", [443])
    assert res["status"] == "Vulnerable"
    assert "CVE-2026-124763" in res["proof"]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "plugin_detected": True,
            "version": "1.1.1",
            "source": "Woocommerce Wishlist readme.txt",
            "is_vulnerable": False,
            "reason": "Patched >= 1.1.1",
        },
    )
    res_safe = plugin.run_audit("10.0.0.50", [443])
    assert res_safe["status"] == "OK"
