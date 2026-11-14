"""
test_wp_ahime_image_printer_audit.py - Unit tests for WordPress Ahime Image Printer File Upload Validation Audit (CVE-2026-124833).
"""

from plugins.wordpress.wp_ahime_image_printer.wp_ahime_image_printer_cve_2026_124833_audit import (
    WPAhimeImagePrinterAuditPlugin,
    parse_ahime_image_printer_version,
    is_ahime_image_printer_version_vulnerable,
)


def test_plugin_metadata():
    plugin = WPAhimeImagePrinterAuditPlugin()
    assert "CVE-2026-124833" in plugin.info["cve"]
    assert plugin.info["severity"] == "CRITICAL"
    assert "Ahime" in plugin.info["name"]


def test_version_parsing():
    html = '<link href="/wp-content/plugins/ahime-image-printer/assets/css/style.css?ver=1.0.0" />'
    assert parse_ahime_image_printer_version(html) == (1, 0, 0, "1.0.0")
    assert parse_ahime_image_printer_version("Stable tag: 1.0.1\n") == (1, 0, 1, "1.0.1")
    assert parse_ahime_image_printer_version("<html>No plugin</html>") is None


def test_version_vulnerability_logic():
    vuln, reason = is_ahime_image_printer_version_vulnerable(1, 0, 0)
    assert vuln is True
    assert "CVE-2026-124833" in reason

    safe, _ = is_ahime_image_printer_version_vulnerable(1, 0, 1)
    assert safe is False


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = WPAhimeImagePrinterAuditPlugin()
    plugin.discovered_ports = [443]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "plugin_detected": True,
            "version": "1.0.0",
            "source": "Ahime Image Printer readme.txt",
            "is_vulnerable": True,
            "reason": "Affected <= 1.0.0 (< 1.0.1)",
        },
    )
    res = plugin.run_audit("10.0.0.50", [443])
    assert res["status"] == "Vulnerable"
    assert "CVE-2026-124833" in res["proof"]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "plugin_detected": True,
            "version": "1.0.1",
            "source": "Ahime Image Printer readme.txt",
            "is_vulnerable": False,
            "reason": "Patched >= 1.0.1",
        },
    )
    res_safe = plugin.run_audit("10.0.0.50", [443])
    assert res_safe["status"] == "OK"
