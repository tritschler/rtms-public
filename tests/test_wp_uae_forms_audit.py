"""
test_wp_uae_forms_audit.py - Unit tests for WordPress Ultimate Addons for Elementor Forms Compliance Audit (CVE-2026-124814).
"""

from plugins.wordpress.wp_uae_forms.wp_uae_forms_cve_2026_124814_audit import (
    WPUAEFormsAuditPlugin,
    parse_uae_forms_version,
    is_uae_forms_version_vulnerable,
)


def test_plugin_metadata():
    plugin = WPUAEFormsAuditPlugin()
    assert plugin.info["cve"] == "CVE-2026-124814"
    assert plugin.info["severity"] == "CRITICAL"
    assert "Elementor Forms" in plugin.info["name"]


def test_version_parsing():
    html = '<script src="/wp-content/plugins/ultimate-addons-for-elementor-forms/assets/js/forms.js?ver=1.0.7"></script>'
    assert parse_uae_forms_version(html) == (1, 0, 7, "1.0.7")
    assert parse_uae_forms_version("Stable tag: 1.0.8\n") == (1, 0, 8, "1.0.8")
    assert parse_uae_forms_version("<html>No plugin</html>") is None


def test_version_vulnerability_logic():
    vuln, reason = is_uae_forms_version_vulnerable(1, 0, 7)
    assert vuln is True
    assert "CVE-2026-124814" in reason

    safe, _ = is_uae_forms_version_vulnerable(1, 0, 8)
    assert safe is False


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = WPUAEFormsAuditPlugin()
    plugin.discovered_ports = [443]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "plugin_detected": True,
            "version": "1.0.7",
            "source": "Ultimate Addons for Elementor Forms readme.txt",
            "is_vulnerable": True,
            "reason": "Affected < 1.0.8",
        },
    )
    res = plugin.run_audit("10.0.0.51", [443])
    assert res["status"] == "Vulnerable"
    assert "CVE-2026-124814" in res["proof"]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "plugin_detected": True,
            "version": "1.0.8",
            "source": "Ultimate Addons for Elementor Forms readme.txt",
            "is_vulnerable": False,
            "reason": "Patched >= 1.0.8",
        },
    )
    res_safe = plugin.run_audit("10.0.0.51", [443])
    assert res_safe["status"] == "OK"
