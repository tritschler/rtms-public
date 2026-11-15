"""
test_wp_fluent_forms_cloud_storage_audit.py - Unit tests for WordPress Cloud Storage Manager for Fluent Forms File Write Audit (CVE-2026-120522).
"""

from plugins.wordpress.wp_fluent_forms_cloud_storage.wp_fluent_forms_cloud_storage_cve_2026_120522_audit import (
    WPFluentFormsCloudStorageAuditPlugin,
    parse_fluent_forms_cloud_storage_version,
    is_fluent_forms_cloud_storage_version_vulnerable,
)


def test_plugin_metadata():
    plugin = WPFluentFormsCloudStorageAuditPlugin()
    assert "CVE-2026-120522" in plugin.info["cve"]
    assert plugin.info["severity"] == "CRITICAL"
    assert "Fluent Forms" in plugin.info["name"]


def test_version_parsing():
    html = '<link href="/wp-content/plugins/cloud-storage-manager-for-fluent-forms/assets/css/style.css?ver=1.2.0" />'
    assert parse_fluent_forms_cloud_storage_version(html) == (1, 2, 0, "1.2.0")
    assert parse_fluent_forms_cloud_storage_version("Stable tag: 1.2.1\n") == (1, 2, 1, "1.2.1")
    assert parse_fluent_forms_cloud_storage_version("<html>No plugin</html>") is None


def test_version_vulnerability_logic():
    vuln, reason = is_fluent_forms_cloud_storage_version_vulnerable(1, 2, 0)
    assert vuln is True
    assert "CVE-2026-120522" in reason

    safe, _ = is_fluent_forms_cloud_storage_version_vulnerable(1, 2, 1)
    assert safe is False


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = WPFluentFormsCloudStorageAuditPlugin()
    plugin.discovered_ports = [443]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "plugin_detected": True,
            "version": "1.2.0",
            "source": "Cloud Storage Manager for Fluent Forms readme.txt",
            "is_vulnerable": True,
            "reason": "Affected <= 1.2.0 (< 1.2.1)",
        },
    )
    res = plugin.run_audit("10.0.0.50", [443])
    assert res["status"] == "Vulnerable"
    assert "CVE-2026-120522" in res["proof"]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "plugin_detected": True,
            "version": "1.2.1",
            "source": "Cloud Storage Manager for Fluent Forms readme.txt",
            "is_vulnerable": False,
            "reason": "Patched >= 1.2.1",
        },
    )
    res_safe = plugin.run_audit("10.0.0.50", [443])
    assert res_safe["status"] == "OK"
