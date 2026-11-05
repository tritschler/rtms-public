"""
test_nomachine_audit.py - Unit tests for NoMachine nxwebrunner Web Service Audit Tool (CVE-2026-114549).
"""

from plugins.nomachine.nomachine_cve_2026_114549_audit import (
    NoMachineAuditPlugin,
    parse_nomachine_version,
    is_nomachine_vulnerable,
)


def test_plugin_metadata():
    plugin = NoMachineAuditPlugin()
    assert plugin.info["cve"] == "CVE-2026-114549"
    assert plugin.info["severity"] == "CRITICAL"
    assert "NoMachine" in plugin.info["name"]
    assert plugin.info["version"] == "1.0.0"
    assert 4443 in plugin.target_ports
    assert 4080 in plugin.target_ports


def test_version_parsing():
    assert parse_nomachine_version(
        "NoMachine/9.7.3"
    ) == (9, 7, 3, "9.7.3")
    assert parse_nomachine_version(
        "<html><title>NoMachine Web Player 9.6.1</title></html>"
    ) == (9, 6, 1, "9.6.1")
    assert parse_nomachine_version(
        "nxwebrunner/9.7.4"
    ) == (9, 7, 4, "9.7.4")
    assert parse_nomachine_version("<html>Apache</html>") is None
    assert parse_nomachine_version("") is None


def test_version_vulnerability_logic():
    vuln, reason = is_nomachine_vulnerable(9, 7, 3, "9.7.3")
    assert vuln is True
    assert "CVE-2026-114549" in reason

    vuln, _ = is_nomachine_vulnerable(9, 5, 0, "9.5.0")
    assert vuln is True

    vuln, reason = is_nomachine_vulnerable(9, 7, 4, "9.7.4")
    assert vuln is False
    assert "patched" in reason


def test_check_requirements():
    plugin = NoMachineAuditPlugin()
    assert plugin.check_requirements("10.0.0.40", [4443, 4080]) is True
    assert 4443 in plugin.discovered_ports
    assert plugin.check_requirements("10.0.0.40", {9443: {"name": "nomachine-web"}}) is True
    assert 9443 in plugin.discovered_ports
    assert plugin.check_requirements("10.0.0.40", [22, 25]) is False


def test_inspect_target_port_vulnerable(mocker):
    plugin = NoMachineAuditPlugin()
    mocker.patch.object(plugin, "probe_http_endpoint", return_value={
        "port": 4443,
        "path": "/",
        "status_code": 200,
        "headers": {"server": "NoMachine/9.7.3"},
        "body_snippet": "<html><title>NoMachine Web Player</title></html>"
    })

    hit = plugin.inspect_target_port("10.0.0.40", 4443)
    assert hit is not None
    assert hit["nomachine_detected"] is True
    assert hit["is_vulnerable"] is True
    assert hit["version"] == "9.7.3"


def test_inspect_target_port_patched(mocker):
    plugin = NoMachineAuditPlugin()
    mocker.patch.object(plugin, "probe_http_endpoint", return_value={
        "port": 4443,
        "path": "/",
        "status_code": 200,
        "headers": {"server": "NoMachine/9.7.4"},
        "body_snippet": "<html><title>NoMachine Web Player</title></html>"
    })

    hit = plugin.inspect_target_port("10.0.0.41", 4443)
    assert hit is not None
    assert hit["nomachine_detected"] is True
    assert hit["is_vulnerable"] is False
    assert hit["version"] == "9.7.4"


def test_inspect_target_port_concealed(mocker):
    plugin = NoMachineAuditPlugin()
    mocker.patch.object(plugin, "probe_http_endpoint", return_value={
        "port": 4443,
        "path": "/nxwebplayer",
        "status_code": 200,
        "headers": {},
        "body_snippet": "<html><title>NoMachine Web Player</title></html>"
    })

    hit = plugin.inspect_target_port("10.0.0.42", 4443)
    assert hit is not None
    assert hit["nomachine_detected"] is True
    assert hit["is_vulnerable"] is False
    assert hit.get("concealed") is True


def test_run_audit_vulnerable_target(mocker):
    plugin = NoMachineAuditPlugin()
    plugin.discovered_ports = [4443]
    mocker.patch.object(plugin, "inspect_target_port", return_value={
        "port": 4443,
        "nomachine_detected": True,
        "version": "9.7.3",
        "source": "HTTP GET /",
        "is_vulnerable": True,
        "reason": "NoMachine 9.7.3 is vulnerable to CVE-2026-114549."
    })

    res = plugin.run_audit("10.0.0.40", [4443])
    assert res["status"] == "Vulnerable"
    assert "CVE-2026-114549" in res["proof"]
    assert "9.7.3" in res["details"]
