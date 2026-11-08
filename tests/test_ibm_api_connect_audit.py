"""
test_ibm_api_connect_audit.py - Unit tests for IBM API Connect Auth Bypass & RCE Audit Tool (CVE-2026-17301).
"""

from plugins.ibm_api_connect.ibm_api_connect_cve_2026_17301_audit import (
    IBMAPIConnectAuditPlugin,
    parse_ibm_apic_version,
    is_ibm_apic_vulnerable,
)


def test_plugin_metadata():
    plugin = IBMAPIConnectAuditPlugin()
    assert plugin.info["cve"] == "CVE-2026-17301"
    assert plugin.info["severity"] == "CRITICAL"
    assert "IBM API Connect" in plugin.info["name"]
    assert plugin.info["version"] == "1.0.0"
    assert 443 in plugin.target_ports
    assert 8443 in plugin.target_ports


def test_version_parsing():
    assert parse_ibm_apic_version(
        '{"productVersion":"10.0.8.11","status":"online"}'
    ) == (10, 0, 8, 11, "10.0.8.11")
    assert parse_ibm_apic_version(
        "IBM API Connect 12.1.1.2"
    ) == (12, 1, 1, 2, "12.1.1.2")
    assert parse_ibm_apic_version(
        "IBM-APIConnect/10.0.8.13"
    ) == (10, 0, 8, 13, "10.0.8.13")
    assert parse_ibm_apic_version("<html>Apache</html>") is None
    assert parse_ibm_apic_version("") is None


def test_version_vulnerability_logic():
    vuln, reason = is_ibm_apic_vulnerable(10, 0, 8, 12, "10.0.8.12")
    assert vuln is True
    assert "CVE-2026-17301" in reason

    vuln, reason = is_ibm_apic_vulnerable(12, 1, 1, 2, "12.1.1.2")
    assert vuln is True
    assert "CVE-2026-17301" in reason

    vuln, _ = is_ibm_apic_vulnerable(12, 1, 0, 1, "12.1.0.1")
    assert vuln is True

    vuln, reason = is_ibm_apic_vulnerable(10, 0, 8, 13, "10.0.8.13")
    assert vuln is False
    assert "patched" in reason

    vuln, reason = is_ibm_apic_vulnerable(12, 1, 1, 3, "12.1.1.3")
    assert vuln is False
    assert "patched" in reason


def test_check_requirements():
    plugin = IBMAPIConnectAuditPlugin()
    assert plugin.check_requirements("10.0.0.70", [443, 8443]) is True
    assert 443 in plugin.discovered_ports
    assert plugin.check_requirements("10.0.0.70", {9443: {"name": "ibm-apiconnect"}}) is True
    assert 9443 in plugin.discovered_ports
    assert plugin.check_requirements("10.0.0.70", [22, 25]) is False


def test_inspect_target_port_vulnerable(mocker):
    plugin = IBMAPIConnectAuditPlugin()
    mocker.patch.object(plugin, "probe_http_endpoint", return_value={
        "port": 443,
        "path": "/api/cloud/settings",
        "status_code": 200,
        "headers": {"server": "IBM-APIConnect"},
        "body_snippet": '{"product":"IBM API Connect","productVersion":"12.1.1.1"}'
    })

    hit = plugin.inspect_target_port("10.0.0.70", 443)
    assert hit is not None
    assert hit["apic_detected"] is True
    assert hit["is_vulnerable"] is True
    assert hit["version"] == "12.1.1.1"


def test_inspect_target_port_patched(mocker):
    plugin = IBMAPIConnectAuditPlugin()
    mocker.patch.object(plugin, "probe_http_endpoint", return_value={
        "port": 443,
        "path": "/api/cloud/settings",
        "status_code": 200,
        "headers": {"server": "IBM-APIConnect"},
        "body_snippet": '{"product":"IBM API Connect","productVersion":"10.0.8.13"}'
    })

    hit = plugin.inspect_target_port("10.0.0.71", 443)
    assert hit is not None
    assert hit["apic_detected"] is True
    assert hit["is_vulnerable"] is False
    assert hit["version"] == "10.0.8.13"


def test_inspect_target_port_concealed(mocker):
    plugin = IBMAPIConnectAuditPlugin()
    mocker.patch.object(plugin, "probe_http_endpoint", return_value={
        "port": 443,
        "path": "/manager/",
        "status_code": 200,
        "headers": {"content-type": "text/html"},
        "body_snippet": "<html><title>IBM API Connect Cloud Manager</title></html>"
    })

    hit = plugin.inspect_target_port("10.0.0.72", 443)
    assert hit is not None
    assert hit["apic_detected"] is True
    assert hit["is_vulnerable"] is False
    assert hit.get("concealed") is True


def test_run_audit_vulnerable_target(mocker):
    plugin = IBMAPIConnectAuditPlugin()
    plugin.discovered_ports = [443]
    mocker.patch.object(plugin, "inspect_target_port", return_value={
        "port": 443,
        "apic_detected": True,
        "version": "12.1.1.1",
        "source": "HTTP GET /api/cloud/settings",
        "is_vulnerable": True,
        "reason": "IBM API Connect 12.1.1.1 is affected by CVE-2026-17301."
    })

    res = plugin.run_audit("10.0.0.70", [443])
    assert res["status"] == "Vulnerable"
    assert "CVE-2026-17301" in res["proof"]
    assert "12.1.1.1" in res["details"]
