"""
test_openam_audit.py - Unit tests for OpenAM Session Token Disclosure & Auth Bypass Audit Tool (CVE-2026-123551).
"""

from plugins.openam.openam_cve_2026_123551_audit import (
    OpenAMAuditPlugin,
    parse_openam_version,
    is_openam_vulnerable,
)


def test_plugin_metadata():
    plugin = OpenAMAuditPlugin()
    assert plugin.info["cve"] == "CVE-2026-123551"
    assert plugin.info["severity"] == "CRITICAL"
    assert "OpenAM" in plugin.info["name"]
    assert plugin.info["version"] == "1.0.0"
    assert 8080 in plugin.target_ports
    assert 8443 in plugin.target_ports


def test_version_parsing():
    assert parse_openam_version(
        '{"version":"16.1.3","revision":"12345","date":"2026"}'
    ) == (16, 1, 3, "16.1.3")
    assert parse_openam_version(
        '{"fullVersion":"OpenAM 15.1.2 Build 456"}'
    ) == (15, 1, 2, "15.1.2")
    assert parse_openam_version(
        "OpenAM/16.1.4"
    ) == (16, 1, 4, "16.1.4")
    assert parse_openam_version(
        '<script src="/openam/XUI/main.js?v=14.8.1"></script>'
    ) == (14, 8, 1, "14.8.1")
    assert parse_openam_version("<html>Nginx</html>") is None
    assert parse_openam_version("") is None


def test_version_vulnerability_logic():
    vuln, reason = is_openam_vulnerable(16, 1, 3, "16.1.3")
    assert vuln is True
    assert "CVE-2026-123551" in reason

    vuln, reason = is_openam_vulnerable(14, 0, 0, "14.0.0")
    assert vuln is True
    assert "CVE-2026-123551" in reason

    vuln, reason = is_openam_vulnerable(13, 5, 1, "13.5.1")
    assert vuln is True
    assert "CVE-2026-123550" in reason

    vuln, reason = is_openam_vulnerable(16, 1, 4, "16.1.4")
    assert vuln is False
    assert "not affected" in reason

    vuln, _ = is_openam_vulnerable(16, 2, 0, "16.2.0")
    assert vuln is False


def test_check_requirements():
    plugin = OpenAMAuditPlugin()
    assert plugin.check_requirements("10.0.0.60", [8080, 8443]) is True
    assert 8080 in plugin.discovered_ports
    assert plugin.check_requirements("10.0.0.60", {9080: {"name": "openam-sso"}}) is True
    assert 9080 in plugin.discovered_ports
    assert plugin.check_requirements("10.0.0.60", [22, 25]) is False


def test_inspect_target_port_vulnerable(mocker):
    plugin = OpenAMAuditPlugin()
    mocker.patch.object(plugin, "probe_http_endpoint", return_value={
        "port": 8080,
        "path": "/openam/json/serverinfo/version",
        "status_code": 200,
        "headers": {"content-type": "application/json"},
        "body_snippet": '{"version":"16.1.2","revision":"abcdef","date":"2026-05-01"}'
    })

    hit = plugin.inspect_target_port("10.0.0.60", 8080)
    assert hit is not None
    assert hit["openam_detected"] is True
    assert hit["is_vulnerable"] is True
    assert hit["version"] == "16.1.2"


def test_inspect_target_port_patched(mocker):
    plugin = OpenAMAuditPlugin()
    mocker.patch.object(plugin, "probe_http_endpoint", return_value={
        "port": 8443,
        "path": "/openam/json/serverinfo/version",
        "status_code": 200,
        "headers": {"content-type": "application/json"},
        "body_snippet": '{"version":"16.1.4","revision":"fedcba","date":"2026-11-08"}'
    })

    hit = plugin.inspect_target_port("10.0.0.61", 8443)
    assert hit is not None
    assert hit["openam_detected"] is True
    assert hit["is_vulnerable"] is False
    assert hit["version"] == "16.1.4"


def test_inspect_target_port_concealed(mocker):
    plugin = OpenAMAuditPlugin()
    mocker.patch.object(plugin, "probe_http_endpoint", return_value={
        "port": 8080,
        "path": "/openam/XUI/",
        "status_code": 200,
        "headers": {"set-cookie": "amlbcookie=01; Path=/"},
        "body_snippet": "<html><title>OpenAM Sign In</title></html>"
    })

    hit = plugin.inspect_target_port("10.0.0.62", 8080)
    assert hit is not None
    assert hit["openam_detected"] is True
    assert hit["is_vulnerable"] is False
    assert hit.get("concealed") is True


def test_run_audit_vulnerable_target(mocker):
    plugin = OpenAMAuditPlugin()
    plugin.discovered_ports = [8080]
    mocker.patch.object(plugin, "inspect_target_port", return_value={
        "port": 8080,
        "openam_detected": True,
        "version": "16.1.2",
        "source": "HTTP GET /openam/json/serverinfo/version",
        "is_vulnerable": True,
        "reason": "OpenAM 16.1.2 is affected by CVE-2026-123551."
    })

    res = plugin.run_audit("10.0.0.60", [8080])
    assert res["status"] == "Vulnerable"
    assert "CVE-2026-123551" in res["proof"]
    assert "16.1.2" in res["details"]
