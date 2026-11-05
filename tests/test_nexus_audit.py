"""
test_nexus_audit.py - Unit tests for Sonatype Nexus Repository 3 Audit Tool (CVE-2026-113373).
"""

from plugins.nexus_repository.nexus_cve_2026_113373_audit import (
    NexusRepositoryAuditPlugin,
    parse_nexus_version,
    is_nexus_vulnerable,
)


def test_plugin_metadata():
    plugin = NexusRepositoryAuditPlugin()
    assert plugin.info["cve"] == "CVE-2026-113373"
    assert plugin.info["severity"] == "CRITICAL"
    assert "Nexus" in plugin.info["name"]
    assert plugin.info["version"] == "1.0.0"
    assert 8081 in plugin.target_ports
    assert 443 in plugin.target_ports


def test_version_parsing():
    assert parse_nexus_version(
        "Nexus/3.90.1-01 (PRO)"
    ) == (3, 90, 1, "3.90.1")
    assert parse_nexus_version(
        '<script src="/static/rapture/nexus-coreui-plugin-prod.js?_v=3.95.2-01"></script>'
    ) == (3, 95, 2, "3.95.2")
    assert parse_nexus_version(
        "Sonatype Nexus Repository Manager 3.98.0"
    ) == (3, 98, 0, "3.98.0")
    assert parse_nexus_version("<html>Nginx</html>") is None
    assert parse_nexus_version("") is None


def test_version_vulnerability_logic():
    vuln, reason = is_nexus_vulnerable(3, 86, 0, "3.86.0")
    assert vuln is True
    assert "CVE-2026-113373" in reason

    vuln, _ = is_nexus_vulnerable(3, 97, 1, "3.97.1")
    assert vuln is True

    vuln, reason = is_nexus_vulnerable(3, 98, 0, "3.98.0")
    assert vuln is False
    assert "not affected" in reason

    vuln, _ = is_nexus_vulnerable(3, 85, 0, "3.85.0")
    assert vuln is False


def test_check_requirements():
    plugin = NexusRepositoryAuditPlugin()
    assert plugin.check_requirements("10.0.0.30", [8081, 443]) is True
    assert 8081 in plugin.discovered_ports
    assert plugin.check_requirements("10.0.0.30", {9081: {"name": "sonatype-nexus"}}) is True
    assert 9081 in plugin.discovered_ports
    assert plugin.check_requirements("10.0.0.30", [22, 25]) is False


def test_inspect_target_port_vulnerable(mocker):
    plugin = NexusRepositoryAuditPlugin()
    mocker.patch.object(plugin, "probe_http_endpoint", return_value={
        "port": 8081,
        "path": "/service/rest/v1/status",
        "status_code": 200,
        "headers": {"server": "Nexus/3.94.1-01 (PRO)"},
        "body_snippet": ""
    })

    hit = plugin.inspect_target_port("10.0.0.30", 8081)
    assert hit is not None
    assert hit["nexus_detected"] is True
    assert hit["is_vulnerable"] is True
    assert hit["version"] == "3.94.1"


def test_inspect_target_port_patched(mocker):
    plugin = NexusRepositoryAuditPlugin()
    mocker.patch.object(plugin, "probe_http_endpoint", return_value={
        "port": 8081,
        "path": "/service/rest/v1/status",
        "status_code": 200,
        "headers": {"server": "Nexus/3.98.0-01 (PRO)"},
        "body_snippet": ""
    })

    hit = plugin.inspect_target_port("10.0.0.31", 8081)
    assert hit is not None
    assert hit["nexus_detected"] is True
    assert hit["is_vulnerable"] is False
    assert hit["version"] == "3.98.0"


def test_inspect_target_port_concealed(mocker):
    plugin = NexusRepositoryAuditPlugin()
    mocker.patch.object(plugin, "probe_http_endpoint", return_value={
        "port": 8081,
        "path": "/",
        "status_code": 200,
        "headers": {"server": "nginx"},
        "body_snippet": "<html><title>Sonatype Nexus Repository</title></html>"
    })

    hit = plugin.inspect_target_port("10.0.0.32", 8081)
    assert hit is not None
    assert hit["nexus_detected"] is True
    assert hit["is_vulnerable"] is False
    assert hit.get("concealed") is True


def test_run_audit_vulnerable_target(mocker):
    plugin = NexusRepositoryAuditPlugin()
    plugin.discovered_ports = [8081]
    mocker.patch.object(plugin, "inspect_target_port", return_value={
        "port": 8081,
        "nexus_detected": True,
        "version": "3.94.1",
        "source": "HTTP GET /service/rest/v1/status",
        "is_vulnerable": True,
        "reason": "Sonatype Nexus Repository 3.94.1 is vulnerable to CVE-2026-113373."
    })

    res = plugin.run_audit("10.0.0.30", [8081])
    assert res["status"] == "Vulnerable"
    assert "CVE-2026-113373" in res["proof"]
    assert "3.94.1" in res["details"]
