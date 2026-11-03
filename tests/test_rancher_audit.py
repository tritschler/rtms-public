"""
test_rancher_audit.py - Unit tests for SUSE Rancher Manager Audit Tool (CVE-2026-88811 / CVE-2026-94290).
"""

from plugins.rancher.rancher_cve_2026_88811_audit import (
    RancherSecurityAuditPlugin,
    parse_rancher_version,
    is_rancher_version_vulnerable,
)


def test_plugin_metadata():
    plugin = RancherSecurityAuditPlugin()
    assert plugin.info["cve"] == "CVE-2026-88811"
    assert plugin.info["severity"] == "CRITICAL"
    assert "Rancher" in plugin.info["name"]
    assert plugin.info["version"] == "1.0.0"


def test_version_parsing():
    assert parse_rancher_version('{"Version":"v2.15.2","GitCommit":"abc1234","RancherPrime":"true"}') == (2, 15, 2, "2.15.2")
    assert parse_rancher_version('{"id":"server-version","value":"v2.14.6"}') == (2, 14, 6, "2.14.6")
    assert parse_rancher_version('{"id":"server-version","value":"v2.13.12"}') == (2, 13, 12, "2.13.12")
    assert parse_rancher_version("<html>Apache Server</html>") is None
    assert parse_rancher_version("") is None


def test_version_vulnerability_logic():
    # Vulnerable branches
    vuln, reason = is_rancher_version_vulnerable(2, 15, 3)
    assert vuln is True
    assert "CVE-2026-88811" in reason

    vuln, _ = is_rancher_version_vulnerable(2, 14, 7)
    assert vuln is True

    vuln, _ = is_rancher_version_vulnerable(2, 13, 11)
    assert vuln is True

    vuln, _ = is_rancher_version_vulnerable(2, 12, 5)
    assert vuln is True

    # Patched versions
    vuln, _ = is_rancher_version_vulnerable(2, 15, 4)
    assert vuln is False

    vuln, _ = is_rancher_version_vulnerable(2, 14, 8)
    assert vuln is False

    vuln, _ = is_rancher_version_vulnerable(2, 13, 12)
    assert vuln is False

    vuln, _ = is_rancher_version_vulnerable(2, 16, 0)
    assert vuln is False


def test_check_requirements():
    plugin = RancherSecurityAuditPlugin()
    assert plugin.check_requirements("10.0.0.10", [443, 8443]) is True
    assert 443 in plugin.discovered_ports
    assert plugin.check_requirements("10.0.0.10", [22, 5432]) is False


def test_inspect_target_port_vulnerable(mocker):
    plugin = RancherSecurityAuditPlugin()
    mocker.patch.object(plugin, "probe_http_endpoint", return_value={
        "port": 443,
        "path": "/rancherversion",
        "status_code": 200,
        "headers": {"x-api-cattle-auth": "false"},
        "body_snippet": '{"Version":"v2.15.2","GitCommit":"9a8b7c","RancherPrime":"false"}'
    })

    hit = plugin.inspect_target_port("10.0.0.50", 443)
    assert hit is not None
    assert hit["rancher_detected"] is True
    assert hit["is_vulnerable"] is True
    assert hit["version"] == "2.15.2"


def test_inspect_target_port_patched(mocker):
    plugin = RancherSecurityAuditPlugin()
    mocker.patch.object(plugin, "probe_http_endpoint", return_value={
        "port": 443,
        "path": "/rancherversion",
        "status_code": 200,
        "headers": {"x-api-cattle-auth": "false"},
        "body_snippet": '{"Version":"v2.15.4","GitCommit":"1a2b3c","RancherPrime":"false"}'
    })

    hit = plugin.inspect_target_port("10.0.0.51", 443)
    assert hit is not None
    assert hit["rancher_detected"] is True
    assert hit["is_vulnerable"] is False
    assert hit["version"] == "2.15.4"


def test_run_audit_vulnerable_target(mocker):
    plugin = RancherSecurityAuditPlugin()
    plugin.discovered_ports = [443]
    mocker.patch.object(plugin, "inspect_target_port", return_value={
        "port": 443,
        "rancher_detected": True,
        "version": "2.14.6",
        "source": "HTTP GET /rancherversion",
        "is_vulnerable": True,
        "reason": "SUSE Rancher v2.14.6 is vulnerable to CVE-2026-88811 & CVE-2026-94290."
    })

    res = plugin.run_audit("10.0.0.50", [443])
    assert res["status"] == "Vulnerable"
    assert "CVE-2026-88811" in res["proof"]
    assert "2.14.6" in res["details"]
