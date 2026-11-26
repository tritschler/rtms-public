"""
test_wp_rocket_audit.py - Unit tests for WordPress WP Rocket
Path Traversal Audit (CVE-2026-125812).
"""

from plugins.wordpress.wp_rocket.wp_rocket_cve_2026_125812_audit import (
    WPRocketAuditPlugin,
    parse_wp_rocket_version,
    is_wp_rocket_version_vulnerable,
)


def test_plugin_metadata():
    plugin = WPRocketAuditPlugin()
    assert "CVE-2026-125812" in plugin.info["cve"]
    assert plugin.info["severity"] == "CRITICAL"
    assert "WP Rocket" in plugin.info["name"]


def test_version_parsing():
    html = '<script src="/wp-content/plugins/wp-rocket/assets/js/lazyload/17.8.3/lazyload.min.js?ver=3.24.1"></script>'
    assert parse_wp_rocket_version(html) == (3, 24, 1, "3.24.1")

    comment = "<!-- This website is like a Rocket, isn't it? Performance optimized by WP Rocket v3.24.1 -->"
    assert parse_wp_rocket_version(comment) == (3, 24, 1, "3.24.1")

    assert parse_wp_rocket_version("Stable tag: 3.24.2\n") == (3, 24, 2, "3.24.2")
    assert parse_wp_rocket_version("<html>No plugin</html>") is None


def test_version_vulnerability_logic():
    vuln, reason = is_wp_rocket_version_vulnerable(3, 24, 1)
    assert vuln is True
    assert "CVE-2026-125812" in reason

    safe, _ = is_wp_rocket_version_vulnerable(3, 24, 2)
    assert safe is False


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = WPRocketAuditPlugin()
    plugin.discovered_ports = [443]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "plugin_detected": True,
            "version": "3.24.1",
            "source": "WP Rocket readme.txt (/wp-content/plugins/wp-rocket/readme.txt)",
            "is_vulnerable": True,
            "reason": "Affected < 3.24.2",
        },
    )
    res = plugin.run_audit("10.0.0.61", [443])
    assert res["status"] == "Vulnerable"
    assert "CVE-2026-125812" in res["proof"]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "plugin_detected": True,
            "version": "3.24.2",
            "source": "WP Rocket readme.txt (/wp-content/plugins/wp-rocket/readme.txt)",
            "is_vulnerable": False,
            "reason": "Patched >= 3.24.2",
        },
    )
    res_safe = plugin.run_audit("10.0.0.61", [443])
    assert res_safe["status"] == "OK"
