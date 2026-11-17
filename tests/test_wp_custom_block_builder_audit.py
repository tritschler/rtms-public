"""
test_wp_custom_block_builder_audit.py - Unit tests for WordPress Custom Block Builder
REST Authorization Audit (CVE-2026-127048).
"""

from plugins.wordpress.wp_custom_block_builder.wp_custom_block_builder_cve_2026_127048_audit import (
    WPCustomBlockBuilderAuditPlugin,
    parse_custom_block_builder_version,
    is_custom_block_builder_version_vulnerable,
)


def test_plugin_metadata():
    plugin = WPCustomBlockBuilderAuditPlugin()
    assert "CVE-2026-127048" in plugin.info["cve"]
    assert plugin.info["severity"] == "CRITICAL"
    assert "Custom Block Builder" in plugin.info["name"]


def test_version_parsing():
    html = '<script src="/wp-content/plugins/custom-block-builder/assets/js/frontend.js?ver=2.9.5"></script>'
    assert parse_custom_block_builder_version(html) == (2, 9, 5, "2.9.5")
    assert parse_custom_block_builder_version("Stable tag: 3.0.0\n") == (3, 0, 0, "3.0.0")
    assert parse_custom_block_builder_version("<html>No plugin</html>") is None


def test_version_vulnerability_logic():
    vuln, reason = is_custom_block_builder_version_vulnerable(2, 9, 5)
    assert vuln is True
    assert "CVE-2026-127048" in reason

    safe, _ = is_custom_block_builder_version_vulnerable(3, 0, 0)
    assert safe is False


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = WPCustomBlockBuilderAuditPlugin()
    plugin.discovered_ports = [443]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "plugin_detected": True,
            "version": "2.9.5",
            "source": "Custom Block Builder readme.txt",
            "is_vulnerable": True,
            "reason": "Affected < 3.0.0",
        },
    )
    res = plugin.run_audit("10.0.0.91", [443])
    assert res["status"] == "Vulnerable"
    assert "CVE-2026-127048" in res["proof"]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "plugin_detected": True,
            "version": "3.0.0",
            "source": "Custom Block Builder readme.txt",
            "is_vulnerable": False,
            "reason": "Patched >= 3.0.0",
        },
    )
    res_safe = plugin.run_audit("10.0.0.91", [443])
    assert res_safe["status"] == "OK"
