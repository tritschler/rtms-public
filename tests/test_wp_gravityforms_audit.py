"""
test_wp_gravityforms_audit.py - Unit tests for WordPress Gravity Forms PHP Object Injection Audit Tool (CVE-2026-103039).
"""

import pytest

from plugins.wordpress.wp_gravityforms.wp_gravityforms_cve_2026_103039_audit import (
    WPGravityFormsAuditPlugin,
    parse_gravityforms_version,
    is_gravityforms_version_vulnerable,
)


def test_plugin_metadata():
    plugin = WPGravityFormsAuditPlugin()
    assert plugin.info["cve"] == "CVE-2026-103039"
    assert plugin.info["severity"] == "CRITICAL"
    assert "Gravity Forms" in plugin.info["name"]
    assert plugin.info["version"] == "1.0.0"


def test_version_parsing():
    # 1. HTML asset URL with ?ver=
    html_snippet = (
        '<link rel="stylesheet" id="gforms_formsmain_css-css" '
        'href="https://example.com/wp-content/plugins/gravityforms/css/formsmain.min.css?ver=3.1.2" />'
    )
    assert parse_gravityforms_version(html_snippet) == (3, 1, 2, "3.1.2")

    # 2. Stable tag or Version header in readme.txt / change_log.txt
    assert parse_gravityforms_version("Stable tag: 3.1.1\nLicense: GPLv2") == (3, 1, 1, "3.1.1")
    assert parse_gravityforms_version("Version: 2.8.17.1") == (2, 8, 17, "2.8.17.1")

    # 3. Changelog markdown header
    assert parse_gravityforms_version("### 3.1.3 | 2026-10-30\n- Fixed security issue.") == (3, 1, 3, "3.1.3")

    # 4. Non-matching strings
    assert parse_gravityforms_version("<html>WordPress 6.7</html>") is None
    assert parse_gravityforms_version("") is None


def test_version_vulnerability_logic():
    # Versions <= 3.1.2 are vulnerable
    vuln, reason = is_gravityforms_version_vulnerable(2, 8, 17)
    assert vuln is True
    assert "CVE-2026-103039" in reason

    vuln, _ = is_gravityforms_version_vulnerable(3, 0, 5)
    assert vuln is True

    vuln, _ = is_gravityforms_version_vulnerable(3, 1, 1)
    assert vuln is True

    vuln, _ = is_gravityforms_version_vulnerable(3, 1, 2)
    assert vuln is True

    # Versions >= 3.1.3 are patched
    vuln, reason = is_gravityforms_version_vulnerable(3, 1, 3)
    assert vuln is False
    assert "patched" in reason

    vuln, _ = is_gravityforms_version_vulnerable(3, 2, 0)
    assert vuln is False


def test_check_requirements():
    plugin = WPGravityFormsAuditPlugin()

    # Ports as list
    assert plugin.check_requirements("10.0.0.10", [80, 443]) is True
    assert 80 in plugin.discovered_ports
    assert 443 in plugin.discovered_ports

    # Service dict
    services = {
        8080: {"name": "http-proxy"},
        8443: {"name": "https-alt"},
        22: {"name": "ssh"},
    }
    assert plugin.check_requirements("10.0.0.10", services) is True
    assert 8080 in plugin.discovered_ports
    assert 8443 in plugin.discovered_ports
    assert 22 not in plugin.discovered_ports

    # Non-web ports only
    assert plugin.check_requirements("10.0.0.10", [22, 25, 3306]) is False
    assert plugin.discovered_ports == []


def test_inspect_target_port_vulnerable_html_asset(mocker):
    plugin = WPGravityFormsAuditPlugin()
    mocker.patch.object(plugin, "probe_http_endpoint", return_value={
        "port": 443,
        "path": "/",
        "status_code": 200,
        "headers": {},
        "body_snippet": (
            '<html><head><script src="/wp-content/plugins/gravityforms/js/gravityforms.min.js?ver=3.1.2">'
            '</script></head><body>Form</body></html>'
        )
    })

    hit = plugin.inspect_target_port("192.168.1.20", 443)
    assert hit is not None
    assert hit["gf_detected"] is True
    assert hit["is_vulnerable"] is True
    assert hit["version"] == "3.1.2"


def test_inspect_target_port_patched_changelog(mocker):
    plugin = WPGravityFormsAuditPlugin()

    def side_effect(target_ip, port, path="/", timeout=4.0):
        if path == "/":
            return {
                "port": port,
                "path": "/",
                "status_code": 200,
                "headers": {},
                "body_snippet": "<html><head><link href='/wp-content/themes/twentytwentyfour/style.css'></head></html>"
            }
        if path == "/wp-content/plugins/gravityforms/change_log.txt":
            return {
                "port": port,
                "path": path,
                "status_code": 200,
                "headers": {},
                "body_snippet": "### Gravity Forms Changelog ###\n\n### 3.1.3 | 2026-10-30\n- Fixed CVE-2026-103039"
            }
        return None

    mocker.patch.object(plugin, "probe_http_endpoint", side_effect=side_effect)

    hit = plugin.inspect_target_port("192.168.1.21", 443)
    assert hit is not None
    assert hit["gf_detected"] is True
    assert hit["is_vulnerable"] is False
    assert hit["version"] == "3.1.3"


def test_inspect_target_port_concealed_version(mocker):
    plugin = WPGravityFormsAuditPlugin()

    def side_effect(target_ip, port, path="/", timeout=4.0):
        if path == "/":
            return {
                "port": port,
                "path": "/",
                "status_code": 200,
                "headers": {},
                "body_snippet": '<div class="gform_wrapper" id="gform_wrapper_1"></div>'
            }
        return None

    mocker.patch.object(plugin, "probe_http_endpoint", side_effect=side_effect)

    hit = plugin.inspect_target_port("192.168.1.22", 80)
    assert hit is not None
    assert hit["gf_detected"] is True
    assert hit["concealed"] is True
    assert hit["is_vulnerable"] is False


def test_run_audit_vulnerable_target(mocker):
    plugin = WPGravityFormsAuditPlugin()
    plugin.discovered_ports = [443]

    mocker.patch.object(plugin, "inspect_target_port", return_value={
        "port": 443,
        "gf_detected": True,
        "version": "3.1.2",
        "source": "HTML asset reference (/wp-content/plugins/gravityforms/...?ver=)",
        "is_vulnerable": True,
        "reason": "Gravity Forms 3.1.2 is vulnerable to CVE-2026-103039 (affected: <= 3.1.2; requires upgrade to >= 3.1.3)."
    })

    res = plugin.run_audit("10.0.0.80", [443])
    assert res["status"] == "Vulnerable"
    assert res["severity"] == "CRITICAL"
    assert "CVE-2026-103039" in res["proof"]
    assert "3.1.2" in res["details"]
    assert "3.1.3" in res["details"]


def test_run_audit_safe_target(mocker):
    plugin = WPGravityFormsAuditPlugin()
    plugin.discovered_ports = [443]

    mocker.patch.object(plugin, "inspect_target_port", return_value={
        "port": 443,
        "gf_detected": True,
        "version": "3.1.3",
        "source": "Gravity Forms change_log.txt",
        "is_vulnerable": False,
        "reason": "Gravity Forms 3.1.3 is patched against CVE-2026-103039 (running >= 3.1.3)."
    })

    res = plugin.run_audit("10.0.0.81", [443])
    assert res["status"] == "OK"
    assert "patched versions" in res["details"]
