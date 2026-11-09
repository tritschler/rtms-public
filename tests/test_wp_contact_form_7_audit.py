"""
test_wp_contact_form_7_audit.py - Unit tests for WordPress Contact Form 7 Version Compliance Audit (CVE-2026-114432).
"""

from plugins.wordpress.wp_contact_form_7.wp_contact_form_7_cve_2026_114432_audit import (
    WPContactForm7AuditPlugin,
    parse_cf7_version,
    is_cf7_version_vulnerable,
)


def test_plugin_metadata():
    plugin = WPContactForm7AuditPlugin()
    assert plugin.info["cve"] == "CVE-2026-114432"
    assert plugin.info["severity"] == "CRITICAL"
    assert "Contact Form 7" in plugin.info["name"]
    assert plugin.info["version"] == "1.0.0"


def test_version_parsing():
    html_snippet = (
        '<link rel="stylesheet" href="https://example.com/wp-content/plugins/'
        'contact-form-7/includes/css/styles.css?ver=6.2.3" />'
    )
    assert parse_cf7_version(html_snippet) == (6, 2, 3, "6.2.3")
    assert parse_cf7_version("Stable tag: 6.2.2\n") == (6, 2, 2, "6.2.2")
    assert parse_cf7_version("= 6.2.4 =\n* Security release") == (6, 2, 4, "6.2.4")
    assert parse_cf7_version("<html>WordPress</html>") is None


def test_version_vulnerability_logic():
    vuln, reason = is_cf7_version_vulnerable(6, 2, 3)
    assert vuln is True
    assert "CVE-2026-114432" in reason

    vuln, _ = is_cf7_version_vulnerable(5, 9, 8)
    assert vuln is True

    vuln, reason = is_cf7_version_vulnerable(6, 2, 4)
    assert vuln is False
    assert "patched" in reason


def test_inspect_target_port_vulnerable_html_asset(mocker):
    plugin = WPContactForm7AuditPlugin()
    mocker.patch.object(plugin, "probe_http_endpoint", return_value={
        "port": 443,
        "path": "/",
        "status_code": 200,
        "headers": {},
        "body_snippet": (
            '<html><head><link href="/wp-content/plugins/contact-form-7/includes/css/styles.css?ver=6.2.3">'
            '</head><body>Contact Us</body></html>'
        ),
    })

    hit = plugin.inspect_target_port("192.168.1.30", 443)
    assert hit is not None
    assert hit["plugin_detected"] is True
    assert hit["is_vulnerable"] is True
    assert hit["version"] == "6.2.3"


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = WPContactForm7AuditPlugin()
    plugin.discovered_ports = [443]

    mocker.patch.object(plugin, "inspect_target_port", return_value={
        "port": 443,
        "plugin_detected": True,
        "version": "6.2.3",
        "source": "Contact Form 7 readme.txt",
        "is_vulnerable": True,
        "reason": "Affected < 6.2.4",
    })
    res = plugin.run_audit("10.0.0.90", [443])
    assert res["status"] == "Vulnerable"
    assert "CVE-2026-114432" in res["proof"]

    mocker.patch.object(plugin, "inspect_target_port", return_value={
        "port": 443,
        "plugin_detected": True,
        "version": "6.2.4",
        "source": "Contact Form 7 readme.txt",
        "is_vulnerable": False,
        "reason": "Patched >= 6.2.4",
    })
    res_safe = plugin.run_audit("10.0.0.90", [443])
    assert res_safe["status"] == "OK"
